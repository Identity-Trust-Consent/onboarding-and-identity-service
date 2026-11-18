package com.identityos.onboarding_and_identity_service.dto;

import java.time.LocalDateTime;
import java.util.UUID;

public record IdentityUserResponse(
        UUID id,
        String applicationId,
        String applicationName,
        String externalUserId,
        String username,
        String email,
        Boolean emailVerified,
        String mobileNumber,
        Boolean mobileVerified,
        String firstName,
        String lastName,
        String status,
        String source,
        LocalDateTime createdAt,
        LocalDateTime updatedAt,
        String subjectId
) {
}
