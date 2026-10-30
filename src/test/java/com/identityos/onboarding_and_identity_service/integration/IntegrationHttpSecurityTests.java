package com.identityos.onboarding_and_identity_service.integration;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import java.util.Map;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
@WebMvcTest(IntegrationDiscoveryController.class)
@Import({IntegrationSecurity.class,IntegrationCorsConfiguration.class})
class IntegrationHttpSecurityTests {
  @Autowired MockMvc mvc;
  @MockitoBean IntegrationService service;
  @MockitoBean JwtDecoder decoder;
  @Test void publicDiscoveryIsSecretFreeAndUncached() throws Exception {
    when(service.discovery("app1")).thenReturn(Map.of("applicationId","app1","clientId","identityos-app1"));
    mvc.perform(get("/.well-known/identity-os-configuration").param("application_id","app1").header("Origin","https://client.example.test"))
      .andExpect(status().isOk()).andExpect(header().string("Cache-Control","no-store"))
      .andExpect(header().string("Access-Control-Allow-Origin","*"))
      .andExpect(jsonPath("$.clientSecret").doesNotExist());
  }
  @Test void directIntegrationRouteRequiresAuthentication() throws Exception {
    mvc.perform(get("/api/v1/integration/applications/app1/me")).andExpect(status().isUnauthorized());
  }
}
