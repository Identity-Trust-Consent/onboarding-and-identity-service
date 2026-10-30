package com.identityos.onboarding_and_identity_service.integration;

import com.identityos.onboarding_and_identity_service.client.KeycloakAdminClient;
import com.identityos.onboarding_and_identity_service.dto.*;
import com.identityos.onboarding_and_identity_service.repository.OrganizationRepository;
import com.identityos.onboarding_and_identity_service.service.OrganizationRegistrationService;
import java.util.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
public class IntegrationService {
  private final IntegrationRepository registry;
  private final OrganizationRepository organizations;
  private final KeycloakAdminClient keycloak;
  private final String issuer;
  private final String publicUrl;
  private final boolean localhost;
  private final Set<String> approvedLegacyIssuers;
  public IntegrationService(IntegrationRepository registry,OrganizationRepository organizations,KeycloakAdminClient keycloak,
      @Value("${integration.issuer}") String issuer,@Value("${integration.public-url}") String publicUrl,
      @Value("${integration.allow-localhost:true}") boolean localhost,
      @Value("${integration.allowed-legacy-issuers:}") String approvedLegacyIssuers) {
    this.registry=registry;this.organizations=organizations;this.keycloak=keycloak;
    this.issuer=issuer;this.publicUrl=publicUrl.replaceAll("/$","");this.localhost=localhost;
    this.approvedLegacyIssuers=new HashSet<>(Arrays.asList(approvedLegacyIssuers.split(",")));
  }
  public record Effective(ApplicationResponse application,IntegrationConfiguration configuration,long organizationVersion,
                          long applicationVersion,boolean provisioned) {}
  public ApplicationResponse application(String id) {
    return organizations.findApplicationByApplicationId(id).orElseThrow(()->new ResponseStatusException(HttpStatus.NOT_FOUND,"Application not found"));
  }
  public Effective effective(String id) {
    var app=application(id);
    var org=organizations.findByOrganizationId(app.organizationId()).orElseThrow();
    if(!"ACTIVE".equals(app.status()) || !"ACTIVE".equals(org.status()) || !"APPROVED".equals(org.approvalStatus()))
      throw new ResponseStatusException(HttpStatus.FORBIDDEN,"Organization or application is not active");
    var parent=registry.read(app.organizationId(),true);var own=registry.read(id,false);
    var config=IntegrationConfiguration.defaults().merge(parent.configuration()).merge(own.configuration());
    config.validate(localhost);
    if(config.allowedLegacyIssuers()!=null && !approvedLegacyIssuers.containsAll(config.allowedLegacyIssuers()))
      throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY,"Legacy issuer must be approved by the platform operator");
    boolean provisioned=own.version()>0 && Objects.equals(own.provisionedVersion(),own.version())
      && Objects.equals(own.provisionedOrganizationVersion(),parent.version());
    return new Effective(app,config,parent.version(),own.version(),provisioned);
  }
  public Map<String,Object> discovery(String id) {
    var e=effective(id);
    if(!e.provisioned()) throw new ResponseStatusException(HttpStatus.CONFLICT,"Integration configuration must be provisioned");
    var result=new LinkedHashMap<String,Object>();
    result.put("version","1.0");result.put("applicationId",id);result.put("organizationId",e.application().organizationId());
    result.put("configurationVersion",e.organizationVersion()+":"+e.applicationVersion());
    result.put("issuer",issuer);result.put("oidcDiscoveryUrl",issuer+"/.well-known/openid-configuration");
    result.put("clientId","identityos-"+id);result.put("audience",id);result.put("clientType",e.configuration().clientType());
    result.put("scopes",e.configuration().scopes());result.put("redirectUris",e.configuration().redirectUris());
    result.put("authorizationUrl",publicUrl+"/api/v1/integration/applications/"+id+"/authorize");
    result.put("identityUrl",publicUrl+"/api/v1/integration/applications/"+id+"/me");
    result.put("capabilities",List.of("oidc-code-pkce","client-credentials","resource-authorization","identity-links","reset-migration"));
    return result;
  }
  @Transactional
  public IntegrationRepository.Versioned configure(String id,boolean org,long expected,IntegrationConfiguration config,Jwt actor) {
    String organizationId=org?id:application(id).organizationId();IntegrationSecurity.admin(actor,organizationId);
    if(config==null) throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Configuration is required");
    config.validate(localhost);
    if(config.allowedLegacyIssuers()!=null && !approvedLegacyIssuers.containsAll(config.allowedLegacyIssuers()))
      throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY,"Legacy issuer must be approved by the platform operator");
    if(org && organizations.findByOrganizationId(id).isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND,"Organization not found");
    if(!org && config.allowedLegacyIssuers()!=null) {
      var parent=IntegrationConfiguration.defaults().merge(registry.read(organizationId,true).configuration());
      if(!parent.allowedLegacyIssuers().containsAll(config.allowedLegacyIssuers()))
        throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY,"Legacy issuers must be approved in organization configuration");
    }
    var saved=registry.save(id,org,expected,config,actor.getSubject());
    registry.audit("INTEGRATION_CONFIGURATION_UPDATED",actor.getSubject(),organizationId,org?null:id,Map.of("version",saved.version()));
    return saved;
  }
  public Map<String,Object> provision(String appId,Jwt actor) {
    var e=effective(appId);IntegrationSecurity.admin(actor,e.application().organizationId());
    if(e.applicationVersion()==0 || e.configuration().redirectUris().isEmpty())
      throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY,"Save application configuration with exact redirect URIs first");
    var result=keycloak.provisionIntegrationClient(appId,e.application().organizationId(),e.configuration());
    registry.provisioned(appId,e.applicationVersion(),e.organizationVersion(),result.get("keycloakClientUuid").toString());
    registry.audit("INTEGRATION_CLIENT_PROVISIONED",actor.getSubject(),e.application().organizationId(),appId,Map.of("version",e.applicationVersion()));
    return result;
  }
  public Map<String,Object> credentials(String appId,Jwt actor) {
    var e=effective(appId);IntegrationSecurity.admin(actor,e.application().organizationId());
    if(!e.provisioned()) throw new ResponseStatusException(HttpStatus.CONFLICT,"Provision current configuration first");
    registry.audit("INTEGRATION_CREDENTIALS_READ",actor.getSubject(),e.application().organizationId(),appId,Map.of());
    return keycloak.integrationCredentials(appId,e.configuration());
  }
  public Map<String,Object> me(String appId,Jwt jwt) {
    var e=effective(appId);validateSubject(e,jwt);
    var identity=registry.identity(appId,jwt.getSubject());
    var result=new LinkedHashMap<String,Object>();result.put("issuer",issuer);result.put("subject",jwt.getSubject());
    result.put("applicationId",appId);result.put("organizationId",e.application().organizationId());
    result.put("legacyAccounts",registry.links(appId,jwt.getSubject()));
    identity.ifPresent(i->{result.put("externalUserId",i.get("external_user_id"));result.put("username",i.get("username"));});
    return result;
  }
  public Map<String,Object> status(String appId,String status,Jwt actor) {
    var app=application(appId);IntegrationSecurity.admin(actor,app.organizationId());
    if(!Set.of("ACTIVE","SUSPENDED").contains(status)) throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY,"Status must be ACTIVE or SUSPENDED");
    organizations.updateApplicationStatus(appId,status);
    registry.audit("INTEGRATION_APPLICATION_"+status,actor.getSubject(),app.organizationId(),appId,Map.of());
    keycloak.setIntegrationClientsEnabled(appId,"ACTIVE".equals(status));
    return Map.of("applicationId",appId,"status",status);
  }
  public void validateSubject(Effective e,Jwt jwt) {
    String id=e.application().applicationId();
    if(!e.provisioned() || !jwt.getAudience().contains(id)
        || !("identityos-"+id).equals(jwt.getClaimAsString("azp"))
        || !id.equals(jwt.getClaimAsString("application_id"))
        || !e.application().organizationId().equals(jwt.getClaimAsString("organization_id"))) IntegrationSecurity.denied();
    var identity=registry.identity(id,jwt.getSubject());
    if(identity.isPresent() && !"ACTIVE".equals(identity.get().get("status"))) IntegrationSecurity.denied();
    if(identity.isEmpty() && !Boolean.TRUE.equals(e.configuration().allowSelfEnrollment())) IntegrationSecurity.denied();
  }
}
