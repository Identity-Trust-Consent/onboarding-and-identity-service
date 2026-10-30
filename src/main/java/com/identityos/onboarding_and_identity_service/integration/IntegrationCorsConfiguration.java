package com.identityos.onboarding_and_identity_service.integration;
import java.util.List;
import org.springframework.context.annotation.*;
import org.springframework.web.cors.*;
@Configuration
public class IntegrationCorsConfiguration {
  @Bean CorsConfigurationSource corsConfigurationSource(IntegrationService integrations) {
    return request->{
      if(request.getHeader("Origin")==null) return null;
      String path=request.getRequestURI();var cors=new CorsConfiguration();
      cors.setAllowCredentials(false);cors.setAllowedHeaders(List.of("Authorization","Content-Type"));
      cors.setAllowedMethods(List.of("GET","POST","OPTIONS"));cors.setMaxAge(300L);
      if(path.startsWith("/api/v1/integration/discovery/") || path.equals("/.well-known/identity-os-configuration")) {
        cors.setAllowedOrigins(List.of("*"));cors.setAllowedMethods(List.of("GET","OPTIONS"));return cors;
      }
      var matcher=java.util.regex.Pattern.compile("^/api/v1/integration/applications/([A-Za-z0-9_-]+)/(me|identity-links)$").matcher(path);
      if(matcher.matches()) {
        try { cors.setAllowedOrigins(integrations.effective(matcher.group(1)).configuration().webOrigins());return cors; }
        catch(org.springframework.web.server.ResponseStatusException missing) { return null; }
      }
      if(!path.startsWith("/api/v1/integration/")) {
        cors.setAllowedOriginPatterns(List.of("http://localhost:*","http://127.0.0.1:*"));
        cors.setAllowedMethods(List.of("GET","POST","PUT","DELETE","OPTIONS"));
        cors.setAllowedHeaders(List.of("*"));return cors;
      }
      return null;
    };
  }
}
