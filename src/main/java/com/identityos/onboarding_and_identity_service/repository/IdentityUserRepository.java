package com.identityos.onboarding_and_identity_service.repository;

import com.identityos.onboarding_and_identity_service.dto.ApplicationResponse;
import com.identityos.onboarding_and_identity_service.dto.IdentityUserResponse;
import com.identityos.onboarding_and_identity_service.dto.UserMigrationUserRequest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.UUID;

@Repository
public class IdentityUserRepository {
    private final JdbcTemplate jdbcTemplate;

    public IdentityUserRepository(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public UUID createBatch(String applicationPublicId, String fileName, int totalRecords, String createdBy) {
        return jdbcTemplate.queryForObject("""
                INSERT INTO identity_user_migration_batch (
                    application_public_id, file_name, total_records, status, created_by
                ) VALUES (?, ?, ?, 'PROCESSING', ?)
                RETURNING id
                """, UUID.class, applicationPublicId, fileName, totalRecords, createdBy);
    }

    public void completeBatch(UUID batchId, int successCount, int failedCount) {
        String status = failedCount == 0 ? "COMPLETED" : successCount == 0 ? "FAILED" : "PARTIAL";
        jdbcTemplate.update("""
                UPDATE identity_user_migration_batch
                SET success_count = ?, failed_count = ?, status = ?, completed_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """, successCount, failedCount, status, batchId);
    }

    public void recordError(UUID batchId, int rowNumber, String username, String errorMessage) {
        jdbcTemplate.update("""
                INSERT INTO identity_user_migration_error (batch_id, row_number, username, error_message)
                VALUES (?, ?, ?, ?)
                """, batchId, rowNumber, username, errorMessage);
    }

    public UUID upsertIdentityUser(
            ApplicationResponse application,
            UserMigrationUserRequest user,
            String keycloakUsername,
            String keycloakUserId,
            String source) {
        UUID applicationUuid = UUID.fromString(application.id());
        String normalizedStatus = normalizeStatus(user.status());
        return jdbcTemplate.queryForObject("""
                INSERT INTO identity_users (
                    application_id, application_public_id, external_user_id, username,
                    keycloak_username, keycloak_user_id, email, email_verified,
                    mobile_number, mobile_verified, first_name, last_name, status, source
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (application_public_id, username)
                DO UPDATE SET
                    external_user_id = EXCLUDED.external_user_id,
                    keycloak_username = EXCLUDED.keycloak_username,
                    keycloak_user_id = COALESCE(EXCLUDED.keycloak_user_id, identity_users.keycloak_user_id),
                    email = EXCLUDED.email,
                    email_verified = EXCLUDED.email_verified,
                    mobile_number = EXCLUDED.mobile_number,
                    mobile_verified = EXCLUDED.mobile_verified,
                    first_name = EXCLUDED.first_name,
                    last_name = EXCLUDED.last_name,
                    status = EXCLUDED.status,
                    source = EXCLUDED.source,
                    updated_at = CURRENT_TIMESTAMP
                RETURNING id
                """,
                UUID.class,
                applicationUuid,
                application.applicationId(),
                user.externalUserId(),
                user.username().trim(),
                keycloakUsername,
                keycloakUserId,
                blankToNull(user.email()),
                user.email() != null && !user.email().isBlank(),
                blankToNull(user.mobileNumber()),
                false,
                blankToNull(user.firstName()),
                blankToNull(user.lastName()),
                normalizedStatus,
                source);
    }

    public void replaceAttributes(UUID identityUserId, Map<String, Object> attributes) {
        if (attributes == null || attributes.isEmpty()) {
            return;
        }
        Set<String> columns = identityUserAttributeColumns();
        if (columns.isEmpty()) {
            throw new IllegalStateException("identity_user_attributes table was not found.");
        }
        String valueColumn = columns.contains("attribute_value") ? "attribute_value" : columns.contains("value") ? "value" : null;
        String sensitiveColumn = columns.contains("sensitive") ? "sensitive" : columns.contains("is_sensitive") ? "is_sensitive" : null;
        if (valueColumn == null) {
            throw new IllegalStateException("identity_user_attributes table must have attribute_value or value column.");
        }
        jdbcTemplate.update("DELETE FROM identity_user_attributes WHERE identity_user_id = ?", identityUserId);
        attributes.forEach((name, value) -> {
            if (name == null || name.isBlank() || value == null) {
                return;
            }
            String cleanName = name.trim();
            String stringValue = String.valueOf(value);
            if (stringValue.isBlank()) {
                return;
            }
            if (sensitiveColumn == null) {
                jdbcTemplate.update("""
                        INSERT INTO identity_user_attributes (
                            identity_user_id, attribute_name, %s
                        ) VALUES (?, ?, ?)
                        """.formatted(valueColumn), identityUserId, cleanName, stringValue);
            } else {
                jdbcTemplate.update("""
                        INSERT INTO identity_user_attributes (
                            identity_user_id, attribute_name, %s, %s
                        ) VALUES (?, ?, ?, ?)
                        """.formatted(valueColumn, sensitiveColumn), identityUserId, cleanName, stringValue, isSensitiveAttribute(cleanName));
            }
        });
    }

    public List<IdentityUserResponse> findByOrganizationId(String organizationId) {
        return jdbcTemplate.query("""
                SELECT iu.id,
                       iu.application_public_id,
                       a.application_name,
                       iu.external_user_id,
                       iu.username,
                       iu.email,
                       iu.email_verified,
                       iu.mobile_number,
                       iu.mobile_verified,
                       iu.first_name,
                       iu.last_name,
                       iu.status,
                       iu.source,
                       iu.created_at,
                       iu.updated_at, iu.keycloak_user_id
                FROM identity_users iu
                JOIN applications a ON a.application_id = iu.application_public_id
                JOIN organizations o ON o.id = a.organization_id
                WHERE o.organization_id = ?
                ORDER BY iu.created_at DESC
                """, (resultSet, rowNum) -> new IdentityUserResponse(
                        (UUID) resultSet.getObject("id"),
                        resultSet.getString("application_public_id"),
                        resultSet.getString("application_name"),
                        resultSet.getString("external_user_id"),
                        resultSet.getString("username"),
                        resultSet.getString("email"),
                        resultSet.getBoolean("email_verified"),
                        resultSet.getString("mobile_number"),
                        resultSet.getBoolean("mobile_verified"),
                        resultSet.getString("first_name"),
                        resultSet.getString("last_name"),
                        resultSet.getString("status"),
                        resultSet.getString("source"),
                        toLocalDateTime(resultSet.getTimestamp("created_at")),
                        toLocalDateTime(resultSet.getTimestamp("updated_at")), resultSet.getString("keycloak_user_id")),
                organizationId);
    }

    public Optional<IdentityUserResponse> findByApplicationAndUsername(String applicationPublicId, String username) {
        return jdbcTemplate.query("""
                SELECT iu.id,
                       iu.application_public_id,
                       a.application_name,
                       iu.external_user_id,
                       iu.username,
                       iu.email,
                       iu.email_verified,
                       iu.mobile_number,
                       iu.mobile_verified,
                       iu.first_name,
                       iu.last_name,
                       iu.status,
                       iu.source,
                       iu.created_at,
                       iu.updated_at, iu.keycloak_user_id
                FROM identity_users iu
                JOIN applications a ON a.application_id = iu.application_public_id
                WHERE iu.application_public_id = ?
                  AND LOWER(iu.username) = LOWER(?)
                """, resultSet -> resultSet.next()
                        ? Optional.of(new IdentityUserResponse(
                        (UUID) resultSet.getObject("id"),
                        resultSet.getString("application_public_id"),
                        resultSet.getString("application_name"),
                        resultSet.getString("external_user_id"),
                        resultSet.getString("username"),
                        resultSet.getString("email"),
                        resultSet.getBoolean("email_verified"),
                        resultSet.getString("mobile_number"),
                        resultSet.getBoolean("mobile_verified"),
                        resultSet.getString("first_name"),
                        resultSet.getString("last_name"),
                        resultSet.getString("status"),
                        resultSet.getString("source"),
                        toLocalDateTime(resultSet.getTimestamp("created_at")),
                        toLocalDateTime(resultSet.getTimestamp("updated_at")), resultSet.getString("keycloak_user_id")))
                        : Optional.empty(),
                applicationPublicId,
                username);
    }

    public Map<String, Object> findAttributes(UUID identityUserId) {
        Set<String> columns = identityUserAttributeColumns();
        if (columns.isEmpty()) {
            return Map.of();
        }
        String valueColumn = columns.contains("attribute_value") ? "attribute_value" : columns.contains("value") ? "value" : null;
        if (valueColumn == null) {
            return Map.of();
        }
        Map<String, Object> attributes = new LinkedHashMap<>();
        jdbcTemplate.query("""
                SELECT attribute_name, %s AS attribute_value
                FROM identity_user_attributes
                WHERE identity_user_id = ?
                """.formatted(valueColumn), resultSet -> {
                    attributes.put(resultSet.getString("attribute_name"), resultSet.getString("attribute_value"));
                }, identityUserId);
        return attributes;
    }

    private Set<String> identityUserAttributeColumns() {
        return jdbcTemplate.queryForList("""
                SELECT column_name
                FROM information_schema.columns
                WHERE table_schema = current_schema()
                  AND table_name = 'identity_user_attributes'
                """, String.class)
                .stream()
                .map(String::toLowerCase)
                .collect(Collectors.toSet());
    }

    private boolean isSensitiveAttribute(String name) {
        String normalized = name.trim().toLowerCase();
        return normalized.contains("aadhaar")
                || normalized.contains("aadhar")
                || normalized.contains("pan")
                || normalized.contains("passport")
                || normalized.contains("dob")
                || normalized.contains("birth")
                || normalized.contains("address")
                || normalized.contains("biometric");
    }

    private String normalizeStatus(String status) {
        if (status == null || status.isBlank()) {
            return "ACTIVE";
        }
        return switch (status.trim().toUpperCase()) {
            case "INACTIVE" -> "INACTIVE";
            case "SUSPENDED" -> "SUSPENDED";
            case "DELETED" -> "DELETED";
            default -> "ACTIVE";
        };
    }

    private String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    private LocalDateTime toLocalDateTime(Timestamp timestamp) {
        return timestamp == null ? null : timestamp.toLocalDateTime();
    }
}
