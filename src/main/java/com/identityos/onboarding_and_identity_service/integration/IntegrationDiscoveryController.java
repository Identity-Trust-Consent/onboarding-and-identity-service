package com.identityos.onboarding_and_identity_service.integration;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
@RestController
public class IntegrationDiscoveryController {
  private final IntegrationService service;
  public IntegrationDiscoveryController(IntegrationService service) { this.service=service; }
  @GetMapping("/.well-known/identity-os-configuration")
  public ResponseEntity<?> discovery(@RequestParam String application_id) {
    return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(service.discovery(application_id));
  }
}
