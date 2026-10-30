package com.identityos.onboarding_and_identity_service.integration;

import com.identityos.onboarding_and_identity_service.dto.*;
import com.identityos.onboarding_and_identity_service.repository.OrganizationRepository;
import com.identityos.onboarding_and_identity_service.service.OrganizationRegistrationService;
import jakarta.validation.Valid;
import java.util.*;
import org.springframework.http.*;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/integration")
public class IntegrationController {
  private final IntegrationService integrations;
  private final IntegrationRepository registry;
  private final OrganizationRepository organizations;
  private final OrganizationRegistrationService registration;
  public IntegrationController(IntegrationService integrations,IntegrationRepository registry,
      OrganizationRepository organizations,OrganizationRegistrationService registration) {
    this.integrations=integrations;this.registry=registry;this.organizations=organizations;this.registration=registration;
  }
  @GetMapping("/discovery/{applicationId}")
  public ResponseEntity<?> discovery(@PathVariable String applicationId) {
    return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(integrations.discovery(applicationId));
  }
  @PostMapping("/organizations")
  public Object registerOrganization(@AuthenticationPrincipal Jwt actor,@Valid @RequestBody RegisterOrganizationRequest request) {
    IntegrationSecurity.admin(actor,""); // Only PLATFORM_ADMIN can register organizations through this secure facade.
    return registration.register(request);
  }
  @PostMapping("/organizations/{organizationId}/applications")
  public Object registerApplication(@PathVariable String organizationId,@AuthenticationPrincipal Jwt actor,
      @Valid @RequestBody ApplicationRegistrationRequest request) {
    IntegrationSecurity.admin(actor,organizationId);
    IntegrationConfiguration.validateUrl(request.redirectUri(),true);
    var app=organizations.insertApplication(organizationId,request);
    registry.audit("INTEGRATION_APPLICATION_REGISTERED",actor.getSubject(),organizationId,app.applicationId(),Map.of());
    return Map.of("applicationId",app.applicationId(),"organizationId",organizationId,"status",app.status());
  }
  @GetMapping("/organizations/{organizationId}/configuration")
  public Object organizationConfiguration(@PathVariable String organizationId,@AuthenticationPrincipal Jwt actor) {
    IntegrationSecurity.admin(actor,organizationId);return registry.read(organizationId,true);
  }
  @PutMapping("/organizations/{organizationId}/configuration")
  public Object organizationConfiguration(@PathVariable String organizationId,@RequestHeader("If-Match") long version,
      @AuthenticationPrincipal Jwt actor,@RequestBody IntegrationConfiguration config) {
    return integrations.configure(organizationId,true,version,config,actor);
  }
  @GetMapping("/applications/{applicationId}/configuration")
  public Object applicationConfiguration(@PathVariable String applicationId,@AuthenticationPrincipal Jwt actor) {
    IntegrationSecurity.admin(actor,integrations.application(applicationId).organizationId());return integrations.effective(applicationId);
  }
  @PutMapping("/applications/{applicationId}/configuration")
  public Object applicationConfiguration(@PathVariable String applicationId,@RequestHeader("If-Match") long version,
      @AuthenticationPrincipal Jwt actor,@RequestBody IntegrationConfiguration config) {
    return integrations.configure(applicationId,false,version,config,actor);
  }
  @PostMapping("/applications/{applicationId}/oidc-client")
  public Object provision(@PathVariable String applicationId,@AuthenticationPrincipal Jwt actor) { return integrations.provision(applicationId,actor); }
  @PostMapping("/applications/{applicationId}/credentials")
  public ResponseEntity<?> credentials(@PathVariable String applicationId,@AuthenticationPrincipal Jwt actor) {
    return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(integrations.credentials(applicationId,actor));
  }
  public record Status(@jakarta.validation.constraints.NotBlank String status) {}
  @PostMapping("/applications/{applicationId}/status")
  public Object status(@PathVariable String applicationId,@AuthenticationPrincipal Jwt actor,@Valid @RequestBody Status request) {
    return integrations.status(applicationId,request.status(),actor);
  }
  @GetMapping("/applications/{applicationId}/me")
  public ResponseEntity<?> me(@PathVariable String applicationId,@AuthenticationPrincipal Jwt actor) {
    return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(integrations.me(applicationId,actor));
  }
}
