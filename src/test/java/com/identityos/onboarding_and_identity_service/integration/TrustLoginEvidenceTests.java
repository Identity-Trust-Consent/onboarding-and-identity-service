package com.identityos.onboarding_and_identity_service.integration;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.identityos.onboarding_and_identity_service.client.trust.TrustSignalClient;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.jwt.*;

class TrustLoginEvidenceTests {
  private TrustSignalClient client(JdbcTemplate jdbc,Jwt jwt) {
    var decoder=mock(JwtDecoder.class);when(decoder.decode("token")).thenReturn(jwt);
    return new TrustSignalClient(jdbc,decoder,"http://localhost:8087","identityos-onboarding-trust","",
      "http://localhost:8085/realms/identity-os/protocol/openid-connect/token",false);
  }
  private Jwt.Builder token() { return Jwt.withTokenValue("token").header("alg","RS256").subject("canonical-subject"); }
  @Test void capturesCanonicalIdentityAndSessionForSharedHostedClientWithoutSavingTokens() throws Exception {
    var jdbc=mock(JdbcTemplate.class);var client=client(jdbc,token().claim("sid","actual-session").build());
    client.recordLogin("token","org","app","canonical-subject");
    var payload=ArgumentCaptor.forClass(String.class);verify(jdbc).update(anyString(),any(UUID.class),payload.capture());
    var json=new ObjectMapper().readTree(payload.getValue());
    assertEquals("canonical-subject",json.path("subjectId").asText());assertEquals("actual-session",json.path("sessionId").asText());
    assertEquals("org",json.path("organizationId").asText());assertEquals("app",json.path("applicationId").asText());
    assertEquals("LOGIN_SUCCESS",json.path("signalType").asText());assertFalse(payload.getValue().contains("accessToken"));
    assertFalse(payload.getValue().contains("password"));
  }
  @Test void rejectsSubjectAndTenantMismatchBeforeQueuing() {
    var jdbc=mock(JdbcTemplate.class);var signed=token().claim("sid","s").claim("organization_id","org").claim("application_id","app").build();
    var client=client(jdbc,signed);
    assertThrows(IllegalStateException.class,()->client.recordLogin("token","org","app","other-subject"));
    assertThrows(IllegalStateException.class,()->client.recordLogin("token","other-org","app","canonical-subject"));
    assertThrows(IllegalStateException.class,()->client.recordLogin("token","org","other-app","canonical-subject"));
    verifyNoInteractions(jdbc);
  }
  @Test void missingSessionIsNotInventedAndOutboxOutageDoesNotFailAnAuthenticatedLogin() {
    var jdbc=mock(JdbcTemplate.class);client(jdbc,token().build()).recordLogin("token","org","app","canonical-subject");
    verifyNoInteractions(jdbc);
    when(jdbc.update(anyString(),any(UUID.class),anyString())).thenThrow(new DataAccessResourceFailureException("test outage"));
    assertDoesNotThrow(()->client(jdbc,token().claim("sid","s").build()).recordLogin("token","org","app","canonical-subject"));
  }
}
