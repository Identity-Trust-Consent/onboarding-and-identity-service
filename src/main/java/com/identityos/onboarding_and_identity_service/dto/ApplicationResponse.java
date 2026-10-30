package com.identityos.onboarding_and_identity_service.dto;

import java.math.BigDecimal;
import java.time.LocalDateTime;

public record ApplicationResponse(
        String id,
        String organizationId,
        String organizationName,
        String applicationId,
        String applicationName,
        String applicationType,
        String description,
        String redirectUri,
        String clientId,
        @com.fasterxml.jackson.annotation.JsonIgnore String clientSecret,
        String status,
        BigDecimal trustScore,
        LocalDateTime createdAt
) {
}
