package com.identityos.onboarding_and_identity_service.integration;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import static org.junit.jupiter.api.Assertions.*;
class IntegrationAuthorizationTests {
  Jwt token(String org,String app,String client,String audience,String scope,List<String> roles) {
    return Jwt.withTokenValue("test").header("alg","RS256").subject("u1").issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60))
      .audience(List.of(audience)).claim("organization_id",org).claim("application_id",app).claim("azp",client)
      .claim("scope",scope).claim("realm_access",Map.of("roles",roles)).build();
  }
  @Test void tenantAdminCannotAccessAnotherOrganization() {
    var admin=token("org1","app1","frontend","identity-os-integration","",List.of("ORGANISATION_ADMIN"));
    assertDoesNotThrow(()->IntegrationSecurity.admin(admin,"org1"));
    assertThrows(org.springframework.web.server.ResponseStatusException.class,()->IntegrationSecurity.admin(admin,"org2"));
  }
  @Test void userCannotImpersonateMachineClientEvenWithScope() {
    var user=token("org1","app1","identityos-app1","identity-os-integration","identityos:authorize",List.of());
    assertThrows(org.springframework.web.server.ResponseStatusException.class,()->IntegrationSecurity.service(user,"app1"));
    var machine=token("org1","app1","identityos-app1-service","identity-os-integration","identityos:authorize",List.of());
    assertDoesNotThrow(()->IntegrationSecurity.service(machine,"app1"));
    assertThrows(org.springframework.web.server.ResponseStatusException.class,()->IntegrationSecurity.service(machine,"app2"));
  }
  @Test void adminRequiresIntegrationAudience() {
    var admin=token("org1","app1","frontend","unrelated-api","",List.of("PLATFORM_ADMIN"));
    assertThrows(org.springframework.web.server.ResponseStatusException.class,()->IntegrationSecurity.admin(admin,"org1"));
  }
}
