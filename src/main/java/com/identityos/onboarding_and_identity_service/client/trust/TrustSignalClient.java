package com.identityos.onboarding_and_identity_service.client.trust;

import com.fasterxml.jackson.databind.*;
import java.time.*;
import java.util.*;
import org.slf4j.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.*;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.RestClient;

@Component
@EnableScheduling
public class TrustSignalClient {
  private static final Logger log=LoggerFactory.getLogger(TrustSignalClient.class);
  private final JdbcTemplate jdbc;
  private final JwtDecoder decoder;
  private final RestClient http;
  private final ObjectMapper mapper=new ObjectMapper();
  private final String trustUrl,client,secret,tokenUrl;
  private final boolean deliveryEnabled;
  private String token;
  private Instant expires=Instant.EPOCH;
  public TrustSignalClient(JdbcTemplate jdbc,JwtDecoder decoder,
      @Value("${services.trust.url:http://localhost:8087}") String trustUrl,
      @Value("${trust.producer.client-id:identityos-onboarding-trust}") String client,
      @Value("${trust.producer.client-secret:}") String secret,
      @Value("${trust.producer.token-url:http://localhost:8085/realms/identity-os/protocol/openid-connect/token}") String tokenUrl,
      @Value("${trust.producer.delivery-enabled:false}") boolean deliveryEnabled) {
    this.jdbc=jdbc;this.decoder=decoder;this.trustUrl=trustUrl;this.client=client;this.secret=secret;this.tokenUrl=tokenUrl;this.deliveryEnabled=deliveryEnabled;
    if(deliveryEnabled && secret.isBlank()) throw new IllegalStateException("Trust producer delivery requires a client secret");
    var factory=new SimpleClientHttpRequestFactory();factory.setConnectTimeout(Duration.ofSeconds(2));factory.setReadTimeout(Duration.ofSeconds(3));
    this.http=RestClient.builder().requestFactory(factory).build();
  }
  /** Legacy registration flags, dummy OTPs and contact-value subjects are not scoring evidence. */
  public void record(String subject,String organization,String application,String type,String outcome,Map<String,Object> metadata) {
    log.debug("Legacy trust event {} excluded from the versioned framework",type);
  }
  public void recordLogin(String accessToken,String organization,String application,String expectedSubject) {
    var jwt=decoder.decode(accessToken);
    // Hosted users use a shared OIDC client. Bind its signed subject to the server's identity registry;
    // per-application clients additionally carry tenant/application claims.
    if(expectedSubject==null || expectedSubject.isBlank() || !expectedSubject.equals(jwt.getSubject())
        || (jwt.getClaimAsString("organization_id")!=null && !organization.equals(jwt.getClaimAsString("organization_id")))
        || (jwt.getClaimAsString("application_id")!=null && !application.equals(jwt.getClaimAsString("application_id"))))
      throw new IllegalStateException("Authenticated identity does not match the trust event tenant/application");
    String session=jwt.getClaimAsString("sid");
    if(session==null || session.isBlank()) { log.warn("Login trust evidence unavailable: token has no session ID");return; }
    UUID id=UUID.randomUUID();
    var payload=Map.of("eventId",id.toString(),"subjectType","USER","subjectId",jwt.getSubject(),"organizationId",organization,
      "applicationId",application,"sessionId",session,"signalType","LOGIN_SUCCESS","outcome","SUCCESS","occurredAt",OffsetDateTime.now().toString());
    try { jdbc.update("insert into trust_signal_outbox(event_id,payload) values (?,?::jsonb)",id,mapper.writeValueAsString(payload)); }
    catch(com.fasterxml.jackson.core.JsonProcessingException ex) { throw new IllegalStateException("Could not serialize trust evidence",ex); }
    catch(org.springframework.dao.DataAccessException unavailable) {
      // Authentication already succeeded. Live Keycloak collection can recover this session's evidence.
      log.warn("Login evidence could not be queued; check trust_signal_outbox migration and database availability");
    }
  }
  private synchronized String token() {
    if(token==null || !expires.isAfter(Instant.now().plusSeconds(30))) {
      var form=new LinkedMultiValueMap<String,String>();form.add("grant_type","client_credentials");
      JsonNode response=http.post().uri(tokenUrl).headers(h -> h.setBasicAuth(client,secret)).contentType(MediaType.APPLICATION_FORM_URLENCODED)
        .body(form).retrieve().body(JsonNode.class);
      if(response==null || !response.hasNonNull("access_token")) throw new IllegalStateException("Trust producer token missing");
      token=response.path("access_token").asText();expires=Instant.now().plusSeconds(response.path("expires_in").asLong(60));
    }
    return token;
  }
  @Scheduled(fixedDelayString="${trust.producer.interval-ms:3000}")
  @Transactional
  public void deliver() {
    if(!deliveryEnabled) return;
    var rows=jdbc.queryForList("select event_id,payload::text from trust_signal_outbox where delivered_at is null order by created_at limit 25 for update skip locked");
    for(var row:rows) {
      try {
        http.post().uri(trustUrl+"/api/v1/trust/signals").headers(h -> h.setBearerAuth(token())).contentType(MediaType.APPLICATION_JSON)
          .body(row.get("payload").toString()).retrieve().toBodilessEntity();
        jdbc.update("update trust_signal_outbox set delivered_at=now(),attempts=attempts+1 where event_id=?",row.get("event_id"));
      } catch(RuntimeException failure) {
        token=null;jdbc.update("update trust_signal_outbox set attempts=attempts+1 where event_id=?",row.get("event_id"));
        log.warn("Trust evidence delivery failed; event {} remains queued",row.get("event_id"));
      }
    }
  }
}
