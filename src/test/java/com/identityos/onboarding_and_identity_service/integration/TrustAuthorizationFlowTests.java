package com.identityos.onboarding_and_identity_service.integration;

import com.identityos.onboarding_and_identity_service.dto.ApplicationResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class TrustAuthorizationFlowTests {
  @Test void mandatoryAndStepUpControlsOverridePermissivePolicyAtZeroApplicationMinimum() throws Exception {
    for(String outcome:List.of("ALLOW","DENY","INCOMPLETE","STEP_UP_AUTHENTICATION")) {
      var server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);var calls=new AtomicInteger();
      server.createContext("/api/v1/trust/integration/evaluate",exchange -> {
        calls.incrementAndGet();
        var request=new ObjectMapper().readTree(exchange.getRequestBody());
        assertEquals("subject",request.path("subjectId").asText());assertEquals("session",request.path("sessionId").asText());
        var response=Map.of("subjectId","subject","organizationId","org","applicationId","app","sessionId","session",
          "evaluationId","evaluation-1","configurationVersion",3,"finalScore",100,"decision",outcome,
          "complete",!outcome.equals("INCOMPLETE"),"mandatoryFailures",outcome.equals("DENY")?List.of("SESSION_VALID_MANDATORY_FAILURE"):List.of());
        byte[] bytes=new ObjectMapper().writeValueAsBytes(response);exchange.getResponseHeaders().set("Content-Type","application/json");
        exchange.sendResponseHeaders(200,bytes.length);exchange.getResponseBody().write(bytes);exchange.close();
      });
      server.createContext("/api/v1/policy/integration/evaluate",exchange -> {
        byte[] bytes="{\"allow\":true}".getBytes(StandardCharsets.UTF_8);exchange.getResponseHeaders().set("Content-Type","application/json");
        exchange.sendResponseHeaders(200,bytes.length);exchange.getResponseBody().write(bytes);exchange.close();
      });server.start();
      try {
        var integrations=mock(IntegrationService.class);var registry=mock(IntegrationRepository.class);var decoder=mock(JwtDecoder.class);
        var application=new ApplicationResponse("id","org","Org","app","App","web","","","client",null,"ACTIVE",null,null);
        var policy=new IntegrationConfiguration.ActionPolicy(List.of(),List.of(),null,List.of(),false);
        var config=new IntegrationConfiguration("public",List.of(),List.of(),List.of(),List.of(),Map.of(),Map.of("read",policy),0.0,false,List.of(),false,Map.of());
        when(integrations.effective("app")).thenReturn(new IntegrationService.Effective(application,config,1,1,true));
        var subject=Jwt.withTokenValue("subject-token").header("alg","RS256").subject("subject").claim("sid","session").build();
        when(decoder.decode("subject-token")).thenReturn(subject);
        var caller=Jwt.withTokenValue("caller").header("alg","RS256").subject("service").audience(List.of("identity-os-integration"))
          .claim("application_id","app").claim("organization_id","org").claim("azp","identityos-app-service").claim("scope","identityos:authorize")
          .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60)).build();
        String url="http://127.0.0.1:"+server.getAddress().getPort();
        var service=new IntegrationAuthorizationService(integrations,registry,decoder,url,url,url);
        var decision=service.authorize("app",caller,new IntegrationAuthorizationService.Request("subject-token","read",
          new IntegrationAuthorizationService.Resource("document","resource","org",null),"correlation"));
        assertEquals(1,calls.get(),"Zero minimum must still call trust");assertEquals(outcome.equals("ALLOW"),decision.allow());
        assertEquals("evaluation-1",decision.trustEvaluationId());assertEquals("3",decision.trustConfigurationVersion());
        if(outcome.equals("DENY")) assertTrue(decision.reasonCodes().contains("MANDATORY_TRUST_CONTROL_FAILED"));
        if(outcome.equals("INCOMPLETE")) assertTrue(decision.reasonCodes().contains("TRUST_EVALUATION_INCOMPLETE"));
        if(outcome.equals("STEP_UP_AUTHENTICATION")) assertTrue(decision.reasonCodes().contains("STEP_UP_REQUIRED"));
      } finally { server.stop(0); }
    }
  }
}
