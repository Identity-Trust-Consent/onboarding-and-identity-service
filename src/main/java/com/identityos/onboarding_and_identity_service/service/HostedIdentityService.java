package com.identityos.onboarding_and_identity_service.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.identityos.onboarding_and_identity_service.client.trust.TrustSignalClient;
import com.identityos.onboarding_and_identity_service.client.KeycloakAdminClient;
import com.identityos.onboarding_and_identity_service.dto.ApplicationResponse;
import com.identityos.onboarding_and_identity_service.dto.HostedIdentityAuthResponse;
import com.identityos.onboarding_and_identity_service.dto.HostedIdentityLoginRequest;
import com.identityos.onboarding_and_identity_service.dto.HostedIdentityProfileCompleteRequest;
import com.identityos.onboarding_and_identity_service.dto.HostedIdentityProfileResponse;
import com.identityos.onboarding_and_identity_service.dto.HostedIdentityRegisterRequest;
import com.identityos.onboarding_and_identity_service.dto.IdentityUserResponse;
import com.identityos.onboarding_and_identity_service.dto.UserMigrationUserRequest;
import com.identityos.onboarding_and_identity_service.repository.IdentityUserRepository;
import com.identityos.onboarding_and_identity_service.repository.OrganizationRepository;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientResponseException;
import org.springframework.web.server.ResponseStatusException;

import java.util.LinkedHashMap;
import java.util.Map;

@Service
public class HostedIdentityService {
    private final OrganizationRepository organizationRepository;
    private final IdentityUserRepository identityUserRepository;
    private final KeycloakAdminClient keycloakAdminClient;
    private final OnboardingAuditService auditService;
    private final TrustSignalClient trustSignalClient;

    public HostedIdentityService(
            OrganizationRepository organizationRepository,
            IdentityUserRepository identityUserRepository,
            KeycloakAdminClient keycloakAdminClient,
            OnboardingAuditService auditService,
            TrustSignalClient trustSignalClient) {
        this.organizationRepository = organizationRepository;
        this.identityUserRepository = identityUserRepository;
        this.keycloakAdminClient = keycloakAdminClient;
        this.auditService = auditService;
        this.trustSignalClient = trustSignalClient;
    }

    public HostedIdentityAuthResponse register(HostedIdentityRegisterRequest request) {
        ApplicationResponse application = approvedApplication(request.clientId(), request.redirectUri());
        String externalUsername = firstPresent(request.fields(), "username", "email", "mobile");
        String password = stringValue(request.fields().get("password"));
        String email = stringValue(request.fields().get("email"));

        if (externalUsername.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Username, email, or mobile is required.");
        }
        if (password.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Password is required.");
        }

        externalUsername = externalUsername(application.applicationId(), externalUsername);
        String keycloakUsername = keycloakUsername(application.applicationId(), externalUsername);
        try {
            String keycloakUserId = keycloakAdminClient.createApplicationUser(
                    keycloakUsername,
                    externalUsername,
                    password,
                    email,
                    application.organizationId(),
                    application.applicationId(),
                    request.clientId(),
                    request.fields());
            HostedIdentityAuthResponse response = new HostedIdentityAuthResponse(
                    true,
                    "Registration completed successfully.",
                    externalUsername,
                    keycloakUserId,
                    null,
                    null,
                    null,
                    null);
            upsertIdentityUser(application, externalUsername, keycloakUsername, keycloakUserId, email, request.fields(), request.verificationStatus(), "SELF_REGISTRATION");
            auditService.hostedIdentityRegistered(
                    application.organizationId(),
                    application.applicationId(),
                    request.clientId(),
                    externalUsername,
                    response);
            recordRegistrationSignals(application, externalUsername, request.verificationStatus());
            return response;
        } catch (IllegalStateException exception) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Registration could not be completed.", exception);
        } catch (RestClientResponseException exception) {
            if (exception.getStatusCode().value() == 409) {
                throw new ResponseStatusException(HttpStatus.CONFLICT, "Username is already registered.", exception);
            }
            String detail = exception.getResponseBodyAsString();
            String message = detail == null || detail.isBlank()
                    ? "Unable to create user in Keycloak."
                    : "Unable to create user in Keycloak: " + detail;
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, message, exception);
        }
    }

    public HostedIdentityAuthResponse login(HostedIdentityLoginRequest request) {
        ApplicationResponse application = approvedApplication(request.clientId(), request.redirectUri());
        String externalUsername = firstPresent(request.fields(), "username", "email", "mobile");
        String password = stringValue(request.fields().get("password"));

        if (externalUsername.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Username, email, or mobile is required.");
        }
        if (password.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Password is required.");
        }
        externalUsername = externalUsername(application.applicationId(), externalUsername);

        JsonNode token;
        try {
            token = authenticateApplicationUser(application.applicationId(), externalUsername, password);
        } catch (HttpClientErrorException.Unauthorized exception) {
            recordLoginSignal(application, externalUsername, "LOGIN_FAILED", "FAILED", Map.of("reason", "unauthorized"));
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid username or password.", exception);
        } catch (HttpClientErrorException.BadRequest exception) {
            String detail = exception.getResponseBodyAsString();
            String message = detail == null || detail.isBlank()
                    ? "Invalid username or password."
                    : "Unable to login through Keycloak: " + detail;
            recordLoginSignal(application, externalUsername, "LOGIN_FAILED", "FAILED", Map.of("reason", message));
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, message, exception);
        }
        HostedIdentityAuthResponse response = new HostedIdentityAuthResponse(
                true,
                "Login successful.",
                externalUsername,
                null,
                token.path("access_token").asText(null),
                token.path("refresh_token").asText(null),
                token.path("token_type").asText("Bearer"),
                token.path("expires_in").isNumber() ? token.path("expires_in").asLong() : null);
        auditService.hostedIdentityLogin(
                application.organizationId(),
                application.applicationId(),
                request.clientId(),
                externalUsername,
                response);
        recordLoginSignal(application, externalUsername, "LOGIN_SUCCESS", "SUCCESS", Map.of("tokenType", response.tokenType()));
        return response;
    }

    public HostedIdentityProfileResponse profile(String clientId, String username) {
        ApplicationResponse application = approvedApplication(clientId, null);
        String externalUsername = externalUsername(application.applicationId(), username);
        IdentityUserResponse user = identityUserRepository.findByApplicationAndUsername(application.applicationId(), externalUsername)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Identity profile was not found."));
        Map<String, Object> attributes = new LinkedHashMap<>(identityUserRepository.findAttributes(user.id()));
        Map<String, Object> fields = new LinkedHashMap<>(attributes);
        fields.put("username", user.username());
        if (user.email() != null && !user.email().isBlank()) fields.put("email", user.email());
        if (user.mobileNumber() != null && !user.mobileNumber().isBlank()) fields.put("mobile", user.mobileNumber());
        if (user.firstName() != null && !user.firstName().isBlank()) fields.put("firstName", user.firstName());
        if (user.lastName() != null && !user.lastName().isBlank()) fields.put("lastName", user.lastName());

        Map<String, Object> verificationStatus = new LinkedHashMap<>();
        verificationStatus.put("email", Map.of("verified", Boolean.TRUE.equals(user.emailVerified())));
        verificationStatus.put("mobile", Map.of("verified", Boolean.TRUE.equals(user.mobileVerified())));
        attributes.forEach((key, value) -> {
            if (key != null && key.endsWith("_verified")) {
                String fieldName = key.substring(0, key.length() - "_verified".length());
                verificationStatus.put(fieldName, Map.of("verified", "true".equalsIgnoreCase(String.valueOf(value))));
            }
        });

        return new HostedIdentityProfileResponse(
                clientId,
                application.organizationId(),
                application.applicationId(),
                application.applicationName(),
                user.username(),
                fields,
                verificationStatus);
    }

    public HostedIdentityProfileResponse completeProfile(HostedIdentityProfileCompleteRequest request) {
        ApplicationResponse application = approvedApplication(request.clientId(), null);
        String externalUsername = externalUsername(application.applicationId(), request.username());
        Map<String, Object> fields = new LinkedHashMap<>(request.fields());
        fields.put("username", externalUsername);
        String keycloakUsername = keycloakUsername(application.applicationId(), externalUsername);
        String email = stringValue(fields.get("email"));
        upsertIdentityUser(application, externalUsername, keycloakUsername, null, email, fields, request.verificationStatus(), "PROFILE_COMPLETION");
        trustSignalClient.record(
                externalUsername,
                application.organizationId(),
                application.applicationId(),
                "PROFILE_COMPLETED",
                "SUCCESS",
                Map.of("source", "profile-completion"));
        recordRegistrationSignals(application, externalUsername, request.verificationStatus());
        return profile(request.clientId(), externalUsername);
    }

    private void recordRegistrationSignals(
            ApplicationResponse application,
            String externalUsername,
            Map<String, Object> verificationStatus) {
        trustSignalClient.record(
                externalUsername,
                application.organizationId(),
                application.applicationId(),
                "IDENTITY_REGISTERED",
                "SUCCESS",
                Map.of("source", "self-registration"));
        if (verificationStatus == null || verificationStatus.isEmpty()) {
            return;
        }
        verificationStatus.forEach((fieldName, value) -> {
            if (!isVerified(value)) {
                return;
            }
            String normalized = fieldName == null ? "" : fieldName.trim().toLowerCase();
            String signalType;
            if (normalized.contains("email")) {
                signalType = "EMAIL_VERIFIED";
            } else if (normalized.contains("mobile") || normalized.contains("phone")) {
                signalType = "MOBILE_VERIFIED";
            } else if (normalized.contains("aadhaar") || normalized.contains("aadhar")) {
                signalType = "AADHAAR_VERIFIED";
            } else if (normalized.contains("pan")) {
                signalType = "PAN_VERIFIED";
            } else {
                signalType = "IDENTITY_FIELD_VERIFIED";
            }
            trustSignalClient.record(
                    externalUsername,
                    application.organizationId(),
                    application.applicationId(),
                    signalType,
                    "SUCCESS",
                    Map.of("fieldName", fieldName == null ? "unknown" : fieldName));
        });
    }

    private void recordLoginSignal(
            ApplicationResponse application,
            String externalUsername,
            String signalType,
            String outcome,
            Map<String, Object> metadata) {
        trustSignalClient.record(
                externalUsername,
                application.organizationId(),
                application.applicationId(),
                signalType,
                outcome,
                metadata);
    }

    private boolean isVerified(Object value) {
        if (value instanceof Map<?, ?> statusMap) {
            Object verifiedValue = statusMap.get("verified");
            return Boolean.TRUE.equals(verifiedValue) || "true".equalsIgnoreCase(String.valueOf(verifiedValue));
        }
        return Boolean.TRUE.equals(value) || "true".equalsIgnoreCase(String.valueOf(value));
    }

    private ApplicationResponse approvedApplication(String clientId, String redirectUri) {
        ApplicationResponse application = organizationRepository.findApplicationByClientId(clientId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Application not found."));
        if (!"ACTIVE".equalsIgnoreCase(application.status())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Application is not active.");
        }
        if (redirectUri != null && !redirectUri.isBlank() && !redirectUri.equals(application.redirectUri())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Redirect URI is not registered for this application.");
        }
        return application;
    }

    private String keycloakUsername(String applicationId, String externalUsername) {
        return (applicationId + "_" + externalUsername.trim().replaceAll("[^A-Za-z0-9._@-]", "_")).toLowerCase();
    }

    private String externalUsername(String applicationId, String username) {
        String trimmed = username.trim();
        String prefix = applicationId.toLowerCase() + "_";
        return trimmed.toLowerCase().startsWith(prefix) ? trimmed.substring(prefix.length()) : trimmed;
    }

    private String legacyKeycloakUsername(String applicationId, String externalUsername) {
        return applicationId + "_" + externalUsername.trim().replaceAll("[^A-Za-z0-9._@-]", "_");
    }

    private JsonNode authenticateApplicationUser(String applicationId, String externalUsername, String password) {
        String normalizedUsername = keycloakUsername(applicationId, externalUsername);
        try {
            return authenticateUsernameWithSetupRepair(normalizedUsername, externalUsername, password);
        } catch (HttpClientErrorException.Unauthorized | HttpClientErrorException.BadRequest exception) {
            String legacyUsername = legacyKeycloakUsername(applicationId, externalUsername);
            if (legacyUsername.equals(normalizedUsername)) {
                throw exception;
            }
            return authenticateUsernameWithSetupRepair(legacyUsername, externalUsername, password);
        }
    }

    private JsonNode authenticateUsernameWithSetupRepair(String keycloakUsername, String externalUsername, String password) {
        // Required actions must be completed in Keycloak, never cleared by an unauthenticated login.
        return keycloakAdminClient.authenticateApplicationUser(keycloakUsername, password);
    }

    private boolean isAccountSetupError(RestClientResponseException exception) {
        String detail = exception.getResponseBodyAsString();
        return detail != null && detail.toLowerCase().contains("account is not fully set up");
    }

    private void upsertIdentityUser(
            ApplicationResponse application,
            String externalUsername,
            String keycloakUsername,
            String keycloakUserId,
            String email,
            Map<String, Object> fields,
            Map<String, Object> verificationStatus,
            String source) {
        try {
            Map<String, Object> attributes = new java.util.LinkedHashMap<>(fields);
            attributes.keySet().removeIf(name -> name.toLowerCase(java.util.Locale.ROOT)
                    .matches(".*(password|secret|token|otp).*"));
            addVerificationAttributes(attributes, verificationStatus);
            UserMigrationUserRequest user = new UserMigrationUserRequest(
                    null,
                    externalUsername,
                    email,
                    stringValue(fields.get("mobile")),
                    stringValue(fields.get("firstName")),
                    stringValue(fields.get("lastName")),
                    "APPLICATION_USER",
                    "ACTIVE",
                    null,
                    attributes);
            java.util.UUID identityUserId = identityUserRepository.upsertIdentityUser(
                    application,
                    user,
                    keycloakUsername,
                    keycloakUserId,
                    source);
            identityUserRepository.replaceAttributes(identityUserId, attributes);
        } catch (RuntimeException exception) {
            System.err.println("Identity OS user table was not updated: " + exception.getMessage());
            throw exception;
        }
    }

    @SuppressWarnings("unchecked")
    private void addVerificationAttributes(Map<String, Object> attributes, Map<String, Object> verificationStatus) {
        if (verificationStatus == null || verificationStatus.isEmpty()) {
            return;
        }
        verificationStatus.forEach((fieldName, value) -> {
            String normalizedFieldName = fieldName == null ? "" : fieldName.trim().toLowerCase().replaceAll("[^a-z0-9]+", "_");
            if (normalizedFieldName.isBlank()) {
                return;
            }
            boolean verified = false;
            String method = "";
            String verifiedAt = "";
            if (value instanceof Map<?, ?> statusMap) {
                Object verifiedValue = statusMap.get("verified");
                verified = Boolean.TRUE.equals(verifiedValue) || "true".equalsIgnoreCase(String.valueOf(verifiedValue));
                Object methodValue = statusMap.get("method");
                Object verifiedAtValue = statusMap.get("verifiedAt");
                method = methodValue == null ? "" : String.valueOf(methodValue);
                verifiedAt = verifiedAtValue == null ? "" : String.valueOf(verifiedAtValue);
            } else {
                verified = Boolean.TRUE.equals(value) || "true".equalsIgnoreCase(String.valueOf(value));
            }
            attributes.put(normalizedFieldName + "_verified", String.valueOf(verified));
            if (!method.isBlank()) {
                attributes.put(normalizedFieldName + "_verification_method", method);
            }
            if (!verifiedAt.isBlank()) {
                attributes.put(normalizedFieldName + "_verified_at", verifiedAt);
            }
        });
    }

    private String firstPresent(Map<String, Object> fields, String... keys) {
        for (String key : keys) {
            String value = stringValue(fields.get(key));
            if (!value.isBlank()) {
                return value;
            }
        }
        return "";
    }

    private String stringValue(Object value) {
        return value == null ? "" : String.valueOf(value).trim();
    }
}
