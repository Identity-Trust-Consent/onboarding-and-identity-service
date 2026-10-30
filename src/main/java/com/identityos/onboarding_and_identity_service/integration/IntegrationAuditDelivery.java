package com.identityos.onboarding_and_identity_service.integration;

import com.fasterxml.jackson.databind.JsonNode;
import java.time.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.*;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.scheduling.annotation.*;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.RestClient;

/** Committed events only. Credentials and tokens are never persisted in the outbox. */
@Component
@EnableScheduling
@ConditionalOnProperty(name="integration.audit-delivery-enabled",havingValue="true")
public class IntegrationAuditDelivery {
  private final IntegrationRepository registry;
  private final RestClient http;
  private final String client,secret,tokenUrl,auditUrl;
  private String token;
  private Instant expires=Instant.EPOCH;
  public IntegrationAuditDelivery(IntegrationRepository registry,
      @Value("${integration.audit-client-id}") String client,@Value("${integration.audit-client-secret}") String secret,
      @Value("${integration.audit-token-url}") String tokenUrl,@Value("${services.audit.url}") String auditUrl) {
    this.registry=registry;this.client=client;this.secret=secret;this.tokenUrl=tokenUrl;this.auditUrl=auditUrl;
    if(client.isBlank() || secret.isBlank()) throw new IllegalStateException("Audit delivery requires platform client credentials");
    var factory=new SimpleClientHttpRequestFactory();factory.setConnectTimeout(Duration.ofSeconds(2));factory.setReadTimeout(Duration.ofSeconds(3));
    http=RestClient.builder().requestFactory(factory).build();
  }
  private synchronized String token() {
    if(token==null || !expires.isAfter(Instant.now().plusSeconds(30))) {
      var form=new LinkedMultiValueMap<String,String>();form.add("grant_type","client_credentials");
      JsonNode response=http.post().uri(tokenUrl).headers(h->h.setBasicAuth(client,secret))
        .contentType(MediaType.APPLICATION_FORM_URLENCODED).body(form).retrieve().body(JsonNode.class);
      token=response.path("access_token").asText();expires=Instant.now().plusSeconds(response.path("expires_in").asLong(60));
    }
    return token;
  }
  @Scheduled(fixedDelayString="${integration.audit-interval-ms:3000}")
  @Transactional
  public void deliver() {
    var pending=registry.jdbc().queryForList("select event_id,payload::text from integration_audit_outbox where delivered_at is null order by created_at limit 25 for update skip locked");
    for(var row:pending) {
      try {
        http.post().uri(auditUrl+"/audits/integration/platform").headers(h->h.setBearerAuth(token()))
          .contentType(MediaType.APPLICATION_JSON).body(row.get("payload").toString()).retrieve().toBodilessEntity();
        registry.jdbc().update("update integration_audit_outbox set delivered_at=now(),attempts=attempts+1 where event_id=?",row.get("event_id"));
      } catch(org.springframework.web.client.RestClientException failure) {
        token=null;registry.jdbc().update("update integration_audit_outbox set attempts=attempts+1 where event_id=?",row.get("event_id"));
      }
    }
  }
}
