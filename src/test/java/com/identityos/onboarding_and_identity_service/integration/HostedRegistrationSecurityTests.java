package com.identityos.onboarding_and_identity_service.integration;
import com.identityos.onboarding_and_identity_service.client.KeycloakAdminClient;
import org.junit.jupiter.api.Test;
import org.springframework.web.client.RestClient;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;
class HostedRegistrationSecurityTests {
  @Test void registeringAnExistingUsernameDoesNotUpdateOrResetTheAccount() throws Exception {
    var server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);var calls=new AtomicInteger();
    server.createContext("/",exchange->{
      calls.incrementAndGet();String path=exchange.getRequestURI().getPath();
      String body=path.endsWith("/token")?"{\"access_token\":\"admin-token\"}":"[{\"id\":\"existing-user\"}]";
      byte[] bytes=body.getBytes(StandardCharsets.UTF_8);exchange.getResponseHeaders().set("Content-Type","application/json");
      exchange.sendResponseHeaders(200,bytes.length);exchange.getResponseBody().write(bytes);exchange.close();
    });server.start();
    try {
      var client=new KeycloakAdminClient(RestClient.builder(),"http://127.0.0.1:"+server.getAddress().getPort(),"identity-os","master","admin-cli","identity-os-app-users","admin","test");
      assertThrows(org.springframework.web.server.ResponseStatusException.class,()->client.createApplicationUser(
        "app_alice","alice","attacker-value","alice@example.test","org","app","app",java.util.Map.of()));
      assertEquals(2,calls.get(),"Duplicate registration must not write any Keycloak state");
    } finally { server.stop(0); }
  }
}
