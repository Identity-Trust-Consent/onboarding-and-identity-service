package com.identityos.onboarding_and_identity_service.integration;
import org.junit.jupiter.api.Test;
import com.fasterxml.jackson.databind.ObjectMapper;
import static org.junit.jupiter.api.Assertions.*;
class IntegrationConfigurationTests {
  final ObjectMapper json=new ObjectMapper();
  @Test void policyCannotWeakenOrganizationMinimums() throws Exception {
    var parent=json.readValue("{\"minimumTrustScore\":80,\"requireConsent\":true}",IntegrationConfiguration.class);
    var app=json.readValue("{\"minimumTrustScore\":0,\"requireConsent\":false}",IntegrationConfiguration.class);
    var effective=IntegrationConfiguration.defaults().merge(parent).merge(app);
    assertEquals(80,effective.minimumTrustScore());assertTrue(effective.requireConsent());
  }
  @Test void redirectsAreExactAndHttpsInProduction() {
    for(String uri:new String[]{"https://example.test/*","http://example.test/callback","//example.test","https://user:pass@example.test/cb","https://example.test/#token"})
      assertThrows(org.springframework.web.server.ResponseStatusException.class,()->IntegrationConfiguration.validateUrl(uri,false));
    assertDoesNotThrow(()->IntegrationConfiguration.validateUrl("http://localhost:3001/",true));
    assertThrows(org.springframework.web.server.ResponseStatusException.class,()->IntegrationConfiguration.validateUrl("http://localhost:3001/",false));
  }
  @Test void interactiveClientCannotMintServiceScope() throws Exception {
    var config=json.readValue("{\"scopes\":[\"openid\",\"identityos:authorize\"]}",IntegrationConfiguration.class);
    assertThrows(org.springframework.web.server.ResponseStatusException.class,()->config.validate(true));
  }
}
