package com.identityos.onboarding_and_identity_service.integration;

import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.http.*;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.transaction.annotation.Transactional;

/** Links require proof of BOTH subjects; email is never a linking key. */
@RestController
@RequestMapping("/api/v1/integration/applications/{applicationId}/identity-links")
public class IntegrationLinkController {
  public record Proof(@NotBlank String legacyIssuer,@NotBlank @Size(max=32000) String legacyAccessToken) {
    @Override public String toString() { return "IdentityLinkProof[redacted]"; }
  }
  private final IntegrationService integrations;
  private final IntegrationRepository registry;
  private final Map<String,JwtDecoder> decoders=new ConcurrentHashMap<>();
  public IntegrationLinkController(IntegrationService integrations,IntegrationRepository registry) { this.integrations=integrations;this.registry=registry; }
  @GetMapping public Object links(@PathVariable String applicationId,@AuthenticationPrincipal Jwt current) {
    integrations.validateSubject(integrations.effective(applicationId),current);
    return registry.links(applicationId,current.getSubject());
  }
  @PostMapping @Transactional
  public ResponseEntity<?> link(@PathVariable String applicationId,@AuthenticationPrincipal Jwt current,@Valid @RequestBody Proof proof) {
    var effective=integrations.effective(applicationId);integrations.validateSubject(effective,current);
    var config=effective.configuration();
    if(!config.allowedLegacyIssuers().contains(proof.legacyIssuer()) || !config.legacyAudiences().containsKey(proof.legacyIssuer()))
      throw new ResponseStatusException(HttpStatus.FORBIDDEN,"Legacy identity provider is not configured");
    // Proofs must be recent. Reauthenticate at both providers before linking.
    if(!recentAuthentication(current))
      throw new ResponseStatusException(HttpStatus.FORBIDDEN,"Recent Identity OS authentication required");
    final Jwt legacy;
    try {
      var decoder=decoders.computeIfAbsent(proof.legacyIssuer(),issuer->JwtDecoders.fromIssuerLocation(issuer));
      legacy=decoder.decode(proof.legacyAccessToken());
      if(legacy.getSubject()==null || legacy.getExpiresAt()==null || !recentAuthentication(legacy)
          || !legacy.getAudience().contains(config.legacyAudiences().get(proof.legacyIssuer()))
          || !"Bearer".equals(legacy.getClaimAsString("typ"))) throw new JwtException("Invalid legacy proof");
    } catch(JwtException | IllegalArgumentException invalid) { throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,"Invalid legacy access token"); }
    registry.link(applicationId,proof.legacyIssuer(),legacy.getSubject(),current.getIssuer().toString(),current.getSubject(),current.getSubject());
    registry.audit("INTEGRATION_IDENTITY_LINKED",current.getSubject(),effective.application().organizationId(),applicationId,
        Map.of("legacyIssuer",proof.legacyIssuer(),"legacySubject",legacy.getSubject()));
    return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(Map.of("linked",true,"legacySubject",legacy.getSubject(),"subject",current.getSubject()));
  }
  private boolean recentAuthentication(Jwt token) {
    Object time=token.getClaims().get("auth_time");
    return time instanceof Number number && number.longValue()>=Instant.now().minusSeconds(300).getEpochSecond()
        && number.longValue()<=Instant.now().plusSeconds(30).getEpochSecond();
  }
}
