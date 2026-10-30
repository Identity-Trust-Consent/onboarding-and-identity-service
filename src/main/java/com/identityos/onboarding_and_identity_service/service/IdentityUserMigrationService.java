package com.identityos.onboarding_and_identity_service.service;

import com.identityos.onboarding_and_identity_service.client.KeycloakAdminClient;
import com.identityos.onboarding_and_identity_service.dto.ApplicationResponse;
import com.identityos.onboarding_and_identity_service.dto.UserMigrationRequest;
import com.identityos.onboarding_and_identity_service.dto.UserMigrationResponse;
import com.identityos.onboarding_and_identity_service.dto.UserMigrationResult;
import com.identityos.onboarding_and_identity_service.dto.UserMigrationUserRequest;
import com.identityos.onboarding_and_identity_service.repository.IdentityUserRepository;
import com.identityos.onboarding_and_identity_service.repository.OrganizationRepository;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
public class IdentityUserMigrationService {
    private final OrganizationRepository organizationRepository;
    private final IdentityUserRepository identityUserRepository;
    private final KeycloakAdminClient keycloakAdminClient;
    private final SecureRandom secureRandom = new SecureRandom();

    public IdentityUserMigrationService(
            OrganizationRepository organizationRepository,
            IdentityUserRepository identityUserRepository,
            KeycloakAdminClient keycloakAdminClient) {
        this.organizationRepository = organizationRepository;
        this.identityUserRepository = identityUserRepository;
        this.keycloakAdminClient = keycloakAdminClient;
    }

    public UserMigrationResponse migrateUsers(UserMigrationRequest request) {
        ApplicationResponse application = organizationRepository.findApplicationByClientId(request.applicationId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Application not found for migration."));
        if (!"ACTIVE".equalsIgnoreCase(application.status())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Application must be active before migration.");
        }

        UUID batchId = identityUserRepository.createBatch(
                application.applicationId(),
                request.fileName(),
                request.users().size(),
                blankToDefault(request.createdBy(), "IDENTITY_OS_ADMIN"));

        List<UserMigrationResult> results = new ArrayList<>();
        int successCount = 0;
        int failedCount = 0;
        for (int index = 0; index < request.users().size(); index++) {
            UserMigrationUserRequest user = request.users().get(index);
            int rowNumber = index + 1;
            try {
                String externalUsername = user.username().trim();
                String keycloakUsername = keycloakUsername(application.applicationId(), externalUsername);
                var existing = identityUserRepository.findByApplicationAndUsername(application.applicationId(), externalUsername);
                if (existing.isPresent()) {
                    if (user.externalUserId() == null || !user.externalUserId().equals(existing.get().externalUserId())) {
                        throw new IllegalArgumentException("Existing username has another identity; resolve the conflict before migration.");
                    }
                    successCount++;
                    results.add(new UserMigrationResult(rowNumber, externalUsername, keycloakUsername, null,
                            "SUCCESS", "Previously migrated identity preserved; credentials were not changed."));
                    continue;
                }
                boolean sendPasswordSetupEmail = Boolean.TRUE.equals(request.sendPasswordSetupEmail());
                String temporaryPassword = sendPasswordSetupEmail ? null : passwordFor(user, request.defaultTemporaryPassword());
                boolean temporaryPasswordRequired = request.temporaryPasswordRequired() == null || request.temporaryPasswordRequired();
                String keycloakUserId = keycloakAdminClient.createMigratedApplicationUser(
                        keycloakUsername,
                        externalUsername,
                        temporaryPassword,
                        temporaryPasswordRequired,
                        sendPasswordSetupEmail,
                        user.email(),
                        user.firstName(),
                        user.lastName(),
                        application.organizationId(),
                        application.applicationId(),
                        application.clientId() == null || application.clientId().isBlank() ? application.applicationId() : application.clientId(),
                        user.role(),
                        attributesFor(user, temporaryPasswordRequired, sendPasswordSetupEmail));

                UUID identityUserId = identityUserRepository.upsertIdentityUser(
                        application,
                        user,
                        keycloakUsername,
                        keycloakUserId,
                        "MIGRATION");
                identityUserRepository.replaceAttributes(identityUserId, user.attributes());
                successCount++;
                results.add(new UserMigrationResult(
                        rowNumber,
                        externalUsername,
                        keycloakUsername,
                        keycloakUserId,
                        "SUCCESS",
                        sendPasswordSetupEmail
                                ? "Migrated successfully. Password setup email sent."
                                : temporaryPasswordRequired
                                ? "Migrated with temporary password. User must change password in Keycloak."
                                : "Migrated successfully."));
            } catch (RuntimeException exception) {
                failedCount++;
                String message = exception.getMessage() == null ? "Migration failed." : exception.getMessage();
                identityUserRepository.recordError(batchId, rowNumber, user.username(), message);
                results.add(new UserMigrationResult(
                        rowNumber,
                        user.username(),
                        null,
                        null,
                        "FAILED",
                        message));
            }
        }

        identityUserRepository.completeBatch(batchId, successCount, failedCount);
        String status = failedCount == 0 ? "COMPLETED" : successCount == 0 ? "FAILED" : "PARTIAL";
        return new UserMigrationResponse(
                batchId.toString(),
                application.applicationId(),
                request.users().size(),
                successCount,
                failedCount,
                status,
                results);
    }

    private Map<String, Object> attributesFor(
            UserMigrationUserRequest user,
            boolean temporaryPasswordRequired,
            boolean passwordSetupEmailSent) {
        Map<String, Object> attributes = new java.util.LinkedHashMap<>();
        if (user.attributes() != null) {
            attributes.putAll(user.attributes());
        }
        attributes.put("migration_source", "IDENTITY_OS_MIGRATION");
        attributes.put("temporary_password_required", String.valueOf(temporaryPasswordRequired));
        attributes.put("password_setup_email_sent", String.valueOf(passwordSetupEmailSent));
        if (user.externalUserId() != null && !user.externalUserId().isBlank()) {
            attributes.put("external_user_id", user.externalUserId());
        }
        return attributes;
    }

    private String passwordFor(UserMigrationUserRequest user, String defaultTemporaryPassword) {
        if (user.temporaryPassword() != null && !user.temporaryPassword().isBlank()) {
            return user.temporaryPassword();
        }
        if (defaultTemporaryPassword != null && !defaultTemporaryPassword.isBlank()) {
            return defaultTemporaryPassword;
        }
        byte[] bytes = new byte[6];
        secureRandom.nextBytes(bytes);
        return "Identity@" + HexFormat.of().formatHex(bytes);
    }

    private String keycloakUsername(String applicationId, String externalUsername) {
        return (applicationId + "_" + externalUsername.trim().replaceAll("[^A-Za-z0-9._@-]", "_")).toLowerCase();
    }

    private String blankToDefault(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value.trim();
    }
}
