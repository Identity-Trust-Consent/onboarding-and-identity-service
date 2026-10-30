package com.identityos.onboarding_and_identity_service.integration;
import jakarta.validation.Valid;
import org.springframework.http.*;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
@RestController
@RequestMapping("/api/v1/integration/applications/{applicationId}")
public class IntegrationAuthorizationController {
  private final IntegrationAuthorizationService service;
  public IntegrationAuthorizationController(IntegrationAuthorizationService service) { this.service=service; }
  @PostMapping("/authorize")
  public ResponseEntity<?> authorize(@PathVariable String applicationId,@AuthenticationPrincipal Jwt caller,
      @Valid @RequestBody IntegrationAuthorizationService.Request request) {
    return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(service.authorize(applicationId,caller,request));
  }
}
