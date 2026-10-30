package com.identityos.onboarding_and_identity_service.integration;

import java.net.URI;
import java.util.*;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

/** Versioned, typed configuration. Organization defaults constrain application overrides. */
public record IntegrationConfiguration(
    String clientType, List<String> redirectUris, List<String> postLogoutRedirectUris,
    List<String> webOrigins, List<String> scopes, Map<String,List<String>> roleMappings,
    Map<String,ActionPolicy> actions, Double minimumTrustScore, Boolean requireConsent,
    List<String> allowedLegacyIssuers, Boolean allowSelfEnrollment, Map<String,String> legacyAudiences) {
  public record ActionPolicy(List<String> roles, List<String> scopes, String consentPurpose,
                             List<String> attributes, Boolean ownerOnly) {}

  public static IntegrationConfiguration defaults() {
    return new IntegrationConfiguration("public", List.of(), List.of(), List.of(),
        List.of("openid","profile","email"), Map.of(), Map.of(), 0.0, false, List.of(), false,Map.of());
  }
  public IntegrationConfiguration merge(IntegrationConfiguration override) {
    if (override == null) return this;
    return new IntegrationConfiguration(
        pick(override.clientType,clientType), pick(override.redirectUris,redirectUris),
        pick(override.postLogoutRedirectUris,postLogoutRedirectUris), pick(override.webOrigins,webOrigins),
        pick(override.scopes,scopes), pick(override.roleMappings,roleMappings), pick(override.actions,actions),
        Math.max(minimumTrustScore == null ? 0 : minimumTrustScore,
                 override.minimumTrustScore == null ? 0 : override.minimumTrustScore),
        Boolean.TRUE.equals(requireConsent) || Boolean.TRUE.equals(override.requireConsent),
        pick(override.allowedLegacyIssuers,allowedLegacyIssuers), pick(override.allowSelfEnrollment,allowSelfEnrollment),
        pick(override.legacyAudiences,legacyAudiences));
  }
  private static <T> T pick(T value,T fallback) { return value == null ? fallback : value; }
  public void validate(boolean allowLocalhost) {
    if (clientType != null && !Set.of("public","confidential").contains(clientType)) bad("Invalid clientType");
    if (minimumTrustScore != null && (!Double.isFinite(minimumTrustScore) || minimumTrustScore<0 || minimumTrustScore>100)) bad("Invalid minimumTrustScore");
    for (var urls : Arrays.asList(redirectUris,postLogoutRedirectUris,webOrigins,allowedLegacyIssuers)) {
      if (urls != null) { if (urls.size()>30) bad("Too many URLs"); for (String value:urls) validateUrl(value,allowLocalhost); }
    }
    if (webOrigins != null) for (String value:webOrigins) {
      URI uri=URI.create(value);
      if (!(uri.getPath().isEmpty() || uri.getPath().equals("/")) || uri.getQuery()!=null) bad("Origins cannot contain paths or queries");
    }
    if (scopes != null && (scopes.size()>50 || scopes.stream().anyMatch(s->s==null || !s.matches("[A-Za-z0-9_.:-]{1,100}")))) bad("Invalid scopes");
    if(scopes!=null && scopes.stream().anyMatch(s->s.startsWith("identityos:"))) bad("Service scopes cannot be granted to interactive clients");
    if(roleMappings!=null && (roleMappings.size()>100 || roleMappings.values().stream().anyMatch(Objects::isNull))) bad("Invalid role mappings");
    if (actions != null) {
      if(actions.size()>100) bad("Too many action policies");
      actions.forEach((name,policy)-> {
        if(name==null || !name.matches("[A-Za-z0-9_.:-]{1,100}") || policy==null) bad("Invalid action policy");
        if(Boolean.TRUE.equals(requireConsent) && (policy.consentPurpose()==null || policy.consentPurpose().isBlank())) bad("Each action requires a consent purpose");
      });
    }
  }
  public static void validateUrl(String value,boolean allowLocalhost) {
    try {
      URI uri=URI.create(value);
      boolean local=allowLocalhost && uri.getHost()!=null && Set.of("localhost","127.0.0.1","[::1]").contains(uri.getHost());
      if(uri.getHost()==null || uri.getUserInfo()!=null || uri.getFragment()!=null || value.contains("*")
          || value.contains("\\") || !("https".equals(uri.getScheme()) || (local && "http".equals(uri.getScheme())))) bad("URLs must be exact HTTPS URLs (localhost HTTP is development-only)");
    } catch(IllegalArgumentException e) { bad("Invalid URL"); }
  }
  private static void bad(String message) { throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY,message); }
}
