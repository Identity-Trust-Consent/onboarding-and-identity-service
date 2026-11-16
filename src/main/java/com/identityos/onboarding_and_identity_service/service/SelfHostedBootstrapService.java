package com.identityos.onboarding_and_identity_service.service;

import com.identityos.onboarding_and_identity_service.client.KeycloakAdminClient;
import com.identityos.onboarding_and_identity_service.dto.RegisterOrganizationRequest;
import com.identityos.onboarding_and_identity_service.repository.OrganizationRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.List;
import java.util.Map;

@Service
public class SelfHostedBootstrapService implements ApplicationRunner {
    private final OrganizationRepository organizationRepository;
    private final KeycloakAdminClient keycloakAdminClient;
    private final boolean enabled;
    private final String organizationId;
    private final String organizationName;
    private final String adminUsername;
    private final String adminName;
    private final String adminEmail;
    private final String adminPassword;
    private final String applicationId;
    private final String applicationName;
    private final String applicationType;
    private final String applicationDescription;
    private final String redirectUri;

    public SelfHostedBootstrapService(
            OrganizationRepository organizationRepository,
            KeycloakAdminClient keycloakAdminClient,
            @Value("${identity-os.self-hosted.enabled:false}") boolean enabled,
            @Value("${identity-os.self-hosted.organization-id:org_self_hosted}") String organizationId,
            @Value("${identity-os.self-hosted.organization-name:Self Hosted Client}") String organizationName,
            @Value("${identity-os.self-hosted.admin.username:}") String adminUsername,
            @Value("${identity-os.self-hosted.admin.name:Application Admin}") String adminName,
            @Value("${identity-os.self-hosted.admin.email:}") String adminEmail,
            @Value("${identity-os.self-hosted.admin.password:}") String adminPassword,
            @Value("${identity-os.self-hosted.application-id:app_b713e8eeab81}") String applicationId,
            @Value("${identity-os.self-hosted.application-name:Employee Management System}") String applicationName,
            @Value("${identity-os.self-hosted.application-type:web}") String applicationType,
            @Value("${identity-os.self-hosted.application-description:Self-hosted application using Identity OS}") String applicationDescription,
            @Value("${identity-os.self-hosted.redirect-uri:http://localhost:9091/callback}") String redirectUri) {
        this.organizationRepository = organizationRepository;
        this.keycloakAdminClient = keycloakAdminClient;
        this.enabled = enabled;
        this.organizationId = organizationId;
        this.organizationName = organizationName;
        this.adminUsername = adminUsername;
        this.adminName = adminName;
        this.adminEmail = adminEmail;
        this.adminPassword = adminPassword;
        this.applicationId = applicationId;
        this.applicationName = applicationName;
        this.applicationType = applicationType;
        this.applicationDescription = applicationDescription;
        this.redirectUri = redirectUri;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (!enabled) {
            return;
        }

        ensureOrganization();
        organizationRepository.ensureSelfHostedApplication(
                organizationId,
                applicationId,
                applicationName,
                applicationType,
                applicationDescription,
                redirectUri);
        ensureDefaultSchemas();
        ensureAdminUser();
    }

    private void ensureOrganization() {
        if (organizationRepository.findByOrganizationId(organizationId).isPresent()) {
            return;
        }
        organizationRepository.insert(new RegisterOrganizationRequest(
                null,
                organizationId,
                organizationName,
                "SELF_HOSTED_CLIENT",
                "IN",
                defaultEmail(),
                "9999999999",
                "SELF-HOSTED-001",
                "Identity OS",
                LocalDate.now(),
                "SELF_HOSTED",
                "SELF-HOSTED-001",
                "VERIFIED",
                "http://localhost:9091",
                null,
                defaultAdminName(),
                defaultEmail(),
                "9999999999",
                "Application Admin",
                null,
                "REGISTERED",
                "-",
                null,
                "-",
                null,
                "-",
                "-",
                null,
                null),
                organizationId);
    }

    private void ensureDefaultSchemas() {
        organizationRepository.ensureApprovedSchemaVersion(
                organizationId,
                applicationId,
                "REGISTRATION",
                "Customer Registration",
                Map.of("registrationFields", List.of(
                        Map.of("name", "email", "type", "email", "label", "Email", "required", true),
                        Map.of("name", "username", "type", "text", "label", "Username", "required", true),
                        Map.of("name", "password", "type", "password", "label", "Password", "required", true)
                )),
                Map.of(
                        "layout", "single-page",
                        "versionedBy", "self-hosted-bootstrap"),
                "Default self-hosted registration schema");

        organizationRepository.ensureApprovedSchemaVersion(
                organizationId,
                applicationId,
                "LOGIN",
                "Default Login",
                Map.of(
                        "loginFields", List.of(
                                Map.of("name", "username", "type", "text", "label", "Username", "required", true),
                                Map.of("name", "password", "type", "password", "label", "Password", "required", true)
                        ),
                        "authenticationMethods", List.of("PASSWORD"),
                        "mfa", false,
                        "mfaMethods", List.of(),
                        "riskAuthentication", false,
                        "flow", List.of("Identifier", "Password Verification", "Token Redirect"),
                        "redirect", Map.of(
                                "clientId", applicationId,
                                "redirectUri", redirectUri,
                                "tokenDelivery", "access-token")),
                Map.of(
                        "renderer", "hosted-identity-os-login",
                        "versionedBy", "self-hosted-bootstrap"),
                "Default self-hosted login schema");
    }

    private void ensureAdminUser() {
        if (adminUsername == null || adminUsername.isBlank()) {
            return;
        }
        try {
            keycloakAdminClient.ensureApplicationSuperAdmin(
                    keycloakAdminUsername(),
                    defaultAdminName(),
                    defaultEmail(),
                    adminPassword,
                    organizationId,
                    applicationId,
                    applicationId);
        } catch (RuntimeException exception) {
            System.err.println("Self-hosted Keycloak admin bootstrap skipped: " + exception.getMessage());
        }
    }

    private String keycloakAdminUsername() {
        String trimmed = adminUsername.trim();
        String prefix = applicationId.toLowerCase() + "_";
        if (trimmed.toLowerCase().startsWith(prefix)) {
            return trimmed.replaceAll("[^A-Za-z0-9._@-]", "_").toLowerCase();
        }
        return (applicationId + "_" + trimmed.replaceAll("[^A-Za-z0-9._@-]", "_")).toLowerCase();
    }

    private String defaultAdminName() {
        return adminName == null || adminName.isBlank() ? "Application Admin" : adminName;
    }

    private String defaultEmail() {
        return adminEmail == null || adminEmail.isBlank() ? "admin@identity-os.local" : adminEmail;
    }
}
