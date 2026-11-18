package com.identityos.onboarding_and_identity_service.integration;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.validation.constraints.*;
import java.time.*;
import java.util.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;
import org.springframework.web.server.ResponseStatusException;

@Service
public class IntegrationAuthorizationService {
  public record Resource(@NotBlank @Size(max=100) String type,@NotBlank @Size(max=255) String id,
                         @NotBlank String organizationId,String ownerSubject) {}
  public record Request(@NotBlank @Size(max=32000) String subjectToken,@NotBlank @Size(max=100) String action,
                        @jakarta.validation.Valid @NotNull Resource resource,@NotBlank @Size(max=100) String correlationId) {
    @Override public String toString() { return "AuthorizationRequest[redacted]"; }
  }
  public record Decision(String decisionId,boolean allow,List<String> reasonCodes,String configurationVersion,
                         String policyVersion,Instant expiresAt,String correlationId,
                         String trustEvaluationId,String trustConfigurationVersion) {}
  private final IntegrationService integrations;
  private final IntegrationRepository registry;
  private final JwtDecoder decoder;
  private final RestClient http;
  private final String trustUrl,consentUrl,policyUrl;
  public IntegrationAuthorizationService(IntegrationService integrations,IntegrationRepository registry,JwtDecoder decoder,
      @Value("${services.trust.url}") String trustUrl,@Value("${integration.consent-url}") String consentUrl,
      @Value("${integration.policy-url}") String policyUrl) {
    this.integrations=integrations;this.registry=registry;this.decoder=decoder;
    this.trustUrl=trustUrl;this.consentUrl=consentUrl;this.policyUrl=policyUrl;
    var factory=new SimpleClientHttpRequestFactory();factory.setConnectTimeout(Duration.ofSeconds(2));factory.setReadTimeout(Duration.ofSeconds(5));
    this.http=RestClient.builder().requestFactory(factory).build();
  }
  public Decision authorize(String appId,Jwt caller,Request request) {
    IntegrationSecurity.service(caller,appId);
    var effective=integrations.effective(appId);
    if(!effective.application().organizationId().equals(caller.getClaimAsString("organization_id"))) IntegrationSecurity.denied();
    final Jwt subject;
    try { subject=decoder.decode(request.subjectToken()); }
    catch(JwtException invalid) { throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,"Invalid subject access token"); }
    integrations.validateSubject(effective,subject);
    var policy=effective.configuration().actions().get(request.action());
    if(policy==null) return decision(effective,subject,request,false,List.of("ACTION_NOT_CONFIGURED"));
    boolean tenant=effective.application().organizationId().equals(request.resource().organizationId());
    boolean owner=!Boolean.TRUE.equals(policy.ownerOnly()) || subject.getSubject().equals(request.resource().ownerSubject());
    Set<String> roles=IntegrationSecurity.roles(subject);
    effective.configuration().roleMappings().forEach((from,to)-> { if(roles.contains(from)) roles.addAll(to); });
    Set<String> scopes=new HashSet<>(Arrays.asList(Optional.ofNullable(subject.getClaimAsString("scope")).orElse("").split(" ")));
    boolean roleAllowed=policy.roles()==null || policy.roles().isEmpty() || policy.roles().stream().anyMatch(roles::contains);
    boolean scopeAllowed=policy.scopes()==null || scopes.containsAll(policy.scopes());
    double score=0;boolean consent=true;
    JsonNode trustResult;
    try {
      String sessionId=subject.getClaimAsString("sid");
      if(sessionId==null || sessionId.isBlank()) return decision(effective,subject,request,false,List.of("SESSION_REQUIRED"));
      // Mandatory trust controls are always evaluated, including when the application's numeric minimum is zero.
      trustResult=post(trustUrl+"/api/v1/trust/integration/evaluate",caller,
          Map.of("subjectId",subject.getSubject(),"sessionId",sessionId));
      if(trustResult==null || !trustResult.path("finalScore").isNumber()
          || !trustResult.path("complete").isBoolean() || !trustResult.path("mandatoryFailures").isArray()
          || !trustResult.path("evaluationId").isTextual() || !trustResult.path("configurationVersion").isNumber()) unavailable();
      score=trustResult.path("finalScore").asDouble();
      if(!Double.isFinite(score) || score<0 || score>100
          || !subject.getSubject().equals(trustResult.path("subjectId").asText())
          || !effective.application().organizationId().equals(trustResult.path("organizationId").asText())
          || !appId.equals(trustResult.path("applicationId").asText())
          || !sessionId.equals(trustResult.path("sessionId").asText())) unavailable();
      boolean mandatoryPassed=trustResult.path("mandatoryFailures").isEmpty();
      boolean trustComplete=trustResult.path("complete").asBoolean();
      boolean trustAllowed="ALLOW".equals(trustResult.path("decision").asText());
      if(Boolean.TRUE.equals(effective.configuration().requireConsent()) || (policy.consentPurpose()!=null && !policy.consentPurpose().isBlank())) {
        if(policy.consentPurpose()==null || policy.consentPurpose().isBlank())
          return decision(effective,subject,request,false,List.of("CONSENT_PURPOSE_NOT_CONFIGURED"));
        // Integration consent is bound to the signed subject; legacy unbound notices cannot grant it.
        String principal=subject.getSubject();
        var consentResult=post(consentUrl+"/api/v1/consent/integration/check",caller,
          Map.of("principal",principal,"purposeCode",policy.consentPurpose(),
            "attributes",policy.attributes()==null?List.of():policy.attributes()));
        if(consentResult==null || !consentResult.path("valid").isBoolean()) unavailable();
        consent=consentResult.path("valid").asBoolean();
      }
      Map<String,Object> input=Map.ofEntries(Map.entry("tenantMatches",tenant),Map.entry("ownerMatches",owner),
          Map.entry("roleAllowed",roleAllowed),Map.entry("scopeAllowed",scopeAllowed),Map.entry("consentValid",consent),
          Map.entry("trustScore",score),Map.entry("minimumTrust",effective.configuration().minimumTrustScore()),Map.entry("active",effective.provisioned()),
          Map.entry("mandatoryPassed",mandatoryPassed),Map.entry("trustComplete",trustComplete),Map.entry("trustAllowed",trustAllowed));
      var evaluated=post(policyUrl+"/api/v1/policy/integration/evaluate",caller,Map.of("input",input));
      if(evaluated==null || !evaluated.path("allow").isBoolean()) unavailable();
      boolean allow=evaluated.path("allow").asBoolean();
      // Defense in depth: no compromised/misconfigured policy response can bypass these bounds.
      allow=allow && tenant && owner && roleAllowed && scopeAllowed && consent && effective.provisioned()
          && score>=effective.configuration().minimumTrustScore() && mandatoryPassed && trustComplete && trustAllowed;
      List<String> reasons=new ArrayList<>();
      if(!tenant) reasons.add("TENANT_MISMATCH");if(!owner) reasons.add("OWNER_MISMATCH");
      if(!roleAllowed) reasons.add("ROLE_REQUIRED");if(!scopeAllowed) reasons.add("SCOPE_REQUIRED");
      if(!consent) reasons.add("CONSENT_REQUIRED");if(score<effective.configuration().minimumTrustScore()) reasons.add("TRUST_THRESHOLD_NOT_MET");
      if(!mandatoryPassed) reasons.add("MANDATORY_TRUST_CONTROL_FAILED");
      if(!trustComplete) reasons.add("TRUST_EVALUATION_INCOMPLETE");
      if(!trustAllowed) reasons.add("STEP_UP_AUTHENTICATION".equals(trustResult.path("decision").asText())?"STEP_UP_REQUIRED":"TRUST_RESTRICTED");
      if(!allow && reasons.isEmpty()) reasons.add("POLICY_DENIED");
      return decision(effective,subject,request,allow,reasons,trustResult);
    } catch(org.springframework.web.client.RestClientException failure) { unavailable();return null; }
  }
  private JsonNode post(String url,Jwt caller,Object body) {
    return http.post().uri(url).headers(h->h.setBearerAuth(caller.getTokenValue())).body(body).retrieve().body(JsonNode.class);
  }
  private Decision decision(IntegrationService.Effective e,Jwt subject,Request request,boolean allow,List<String> reasons) {
    return decision(e,subject,request,allow,reasons,null);
  }
  private Decision decision(IntegrationService.Effective e,Jwt subject,Request request,boolean allow,List<String> reasons,JsonNode trust) {
    String id=UUID.randomUUID().toString();
    registry.audit("INTEGRATION_AUTHORIZATION_"+(allow?"ALLOWED":"DENIED"),subject.getSubject(),
      e.application().organizationId(),e.application().applicationId(),Map.of("decisionId",id,"action",request.action(),
        "resourceType",request.resource().type(),"resourceId",request.resource().id(),"reasonCodes",reasons,"correlationId",request.correlationId(),
        "trustEvaluationId",trust==null?"":trust.path("evaluationId").asText(),"trustConfigurationVersion",trust==null?"":trust.path("configurationVersion").asText()));
    return new Decision(id,allow,reasons,e.organizationVersion()+":"+e.applicationVersion(),"identityos.integration.v1",
        Instant.now().plusSeconds(10),request.correlationId(),trust==null?null:trust.path("evaluationId").asText(),
        trust==null?null:trust.path("configurationVersion").asText());
  }
  private static void unavailable() { throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,"Authoritative policy dependency unavailable"); }
}
