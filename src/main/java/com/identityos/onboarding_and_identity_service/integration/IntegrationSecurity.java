package com.identityos.onboarding_and_identity_service.integration;

import java.util.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.*;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

@Configuration
public class IntegrationSecurity {
  @Bean
  JwtDecoder integrationJwtDecoder(@Value("${integration.issuer}") String issuer,
      @Value("${integration.jwks-uri}") String jwks) {
    var decoder=NimbusJwtDecoder.withJwkSetUri(jwks).build();
    decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(JwtValidators.createDefaultWithIssuer(issuer),jwt ->
      jwt.getSubject()!=null && "Bearer".equals(jwt.getClaimAsString("typ")) && jwt.getExpiresAt()!=null
        ? OAuth2TokenValidatorResult.success() : OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token"))));
    return decoder;
  }
  @Bean
  SecurityFilterChain integrationFilterChain(HttpSecurity http,
      @Value("${integration.legacy-api-enabled:true}") boolean legacy) throws Exception {
    // The compatibility chain preserves legacy routes. Production explicitly disables legacy API access.
    http.cors(c->{}).sessionManagement(s->s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
      .csrf(c->c.disable()).authorizeHttpRequests(a->{
        a.requestMatchers("/actuator/health","/actuator/health/**",
            "/.well-known/identity-os-configuration","/api/v1/integration/discovery/**").permitAll();
        a.requestMatchers("/api/v1/integration/**").authenticated();
        if(legacy) a.anyRequest().permitAll(); else a.anyRequest().denyAll();
      }).oauth2ResourceServer(o->o.jwt(j->{}));
    return http.build();
  }
  public static Set<String> roles(Jwt jwt) {
    Set<String> result=new HashSet<>();
    var access=jwt.getClaimAsMap("realm_access");
    if(access!=null && access.get("roles") instanceof Collection<?> values) values.forEach(v->result.add(v.toString()));
    return result;
  }
  public static void admin(Jwt jwt,String organizationId) {
    if(!jwt.getAudience().contains("identity-os-integration")) denied();
    Set<String> roles=roles(jwt);
    if(roles.contains("PLATFORM_ADMIN")) return;
    if(!roles.contains("ORGANISATION_ADMIN") || !organizationId.equals(jwt.getClaimAsString("organization_id"))) denied();
  }
  public static void service(Jwt jwt,String applicationId) {
    if(!jwt.getAudience().contains("identity-os-integration")
        || !applicationId.equals(jwt.getClaimAsString("application_id"))
        || !("identityos-"+applicationId+"-service").equals(jwt.getClaimAsString("azp"))
        || !Arrays.asList(Optional.ofNullable(jwt.getClaimAsString("scope")).orElse("").split(" ")).contains("identityos:authorize")) denied();
  }
  public static void denied() { throw new ResponseStatusException(HttpStatus.FORBIDDEN,"Integration access denied"); }
}
