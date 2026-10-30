package com.identityos.onboarding_and_identity_service.client;

import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

@Component
public class KeycloakAdminClient {
    private final RestClient restClient;
    private final String targetRealm;
    private final String adminRealm;
    private final String clientId;
    private final String userClientId;
    private final String username;
    private final String password;
    @Value("${keycloak.admin.client-secret:}")
    private String adminClientSecret = "";

    public KeycloakAdminClient(
            RestClient.Builder builder,
            @Value("${keycloak.admin.base-url}") String baseUrl,
            @Value("${keycloak.admin.target-realm}") String targetRealm,
            @Value("${keycloak.admin.admin-realm}") String adminRealm,
            @Value("${keycloak.admin.client-id}") String clientId,
            @Value("${keycloak.admin.user-client-id}") String userClientId,
            @Value("${keycloak.admin.username}") String username,
            @Value("${keycloak.admin.password}") String password) {
        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setConnectTimeout(Duration.ofSeconds(5));
        requestFactory.setReadTimeout(Duration.ofSeconds(8));
        this.restClient = builder.baseUrl(baseUrl).requestFactory(requestFactory).build();
        this.targetRealm = targetRealm;
        this.adminRealm = adminRealm;
        this.clientId = clientId;
        this.userClientId = userClientId;
        this.username = username;
        this.password = password;
    }

    public boolean createOrganizationAdmin(String organizationId, String representativeName, String email) {
        String token = requestAdminToken();
        String userId = findUserIdByUsername(token, organizationId);
        boolean userCreated = false;
        if (userId == null) {
            userId = createUser(token, organizationId, representativeName, email);
            userCreated = true;
        } else {
            updateUser(token, userId, organizationId, representativeName, email);
        }
        try {
            assignOrganizationAdminRole(token, userId);
        } catch (RuntimeException exception) {
            if (userCreated) {
                deleteUser(token, userId);
            }
            throw exception;
        }

        try {
            sendVerificationEmail(token, userId);
            return true;
        } catch (RuntimeException exception) {
            // SMTP is optional in local development; the user remains provisioned.
            System.err.println("Keycloak verification email was not sent: " + exception.getMessage());
            return false;
        }
    }

    public void ensureApplicationSuperAdmin(
            String adminUsername,
            String displayName,
            String email,
            String password,
            String organizationId,
            String applicationId,
            String clientId) {
        String token = requestAdminToken();
        String userId = findUserIdByUsername(token, adminUsername);
        if (userId == null) {
            userId = createSelfHostedAdminUser(
                    token,
                    adminUsername,
                    displayName,
                    email,
                    password,
                    organizationId,
                    applicationId,
                    clientId);
        } else {
            updateSelfHostedAdminUser(
                    token,
                    userId,
                    adminUsername,
                    displayName,
                    email,
                    organizationId,
                    applicationId,
                    clientId);
            if (password != null && !password.isBlank()) {
                resetApplicationUserPassword(token, userId, password);
            }
        }
        assignRealmRole(token, userId, "APPLICATION_SUPER_ADMIN", "Self-hosted application administrator");
        assignRealmRole(token, userId, "APPLICATION_USER", "End user registered through a third-party application");
    }

    public String createApplicationUser(
            String keycloakUsername,
            String externalUsername,
            String password,
            String email,
            String organizationId,
            String applicationId,
            String clientId,
            Map<String, Object> submittedFields) {
        String token = requestAdminToken();
        String userId = findUserIdByUsername(token, keycloakUsername);
        if (userId != null) throw new org.springframework.web.server.ResponseStatusException(
                org.springframework.http.HttpStatus.CONFLICT, "Username is already registered.");
        String usersGroupId = ensureGroupHierarchy(token, organizationId, applicationId);
        if (userId == null) {
            userId = createApplicationUserInKeycloak(
                    token,
                    keycloakUsername,
                    externalUsername,
                    password,
                    email,
                    organizationId,
                    applicationId,
                    clientId,
                    submittedFields);
        } else {
            // Registration must never serve as unauthenticated password recovery.
            throw new org.springframework.web.server.ResponseStatusException(
                    org.springframework.http.HttpStatus.CONFLICT, "Username is already registered.");
        }
        joinGroup(token, userId, usersGroupId);
        assignApplicationUserRole(token, userId);
        return userId;
    }

    public String createMigratedApplicationUser(
            String keycloakUsername,
            String externalUsername,
            String password,
            boolean temporaryPassword,
            boolean sendPasswordSetupEmail,
            String email,
            String firstName,
            String lastName,
            String organizationId,
            String applicationId,
            String clientId,
            String roleName,
            Map<String, Object> submittedFields) {
        String token = requestAdminToken();
        String userId = findUserIdByUsername(token, keycloakUsername);
        if (userId != null) {
            JsonNode existing = getUser(token, userId);
            String externalId = submittedFields == null ? "" : String.valueOf(submittedFields.getOrDefault("external_user_id", ""));
            if (externalId.isBlank()
                    || !externalId.equals(existing.path("attributes").path("external_user_id").path(0).asText())
                    || !applicationId.equals(existing.path("attributes").path("application_id").path(0).asText())
                    || !organizationId.equals(existing.path("attributes").path("organization_id").path(0).asText())) {
                throw new IllegalStateException("Keycloak username collision requires explicit identity reconciliation.");
            }
            // Resume a partially completed import without resetting credentials, email or required actions.
            return userId;
        }
        String usersGroupId = ensureGroupHierarchy(token, organizationId, applicationId);
        Map<String, Object> fields = new LinkedHashMap<>();
        if (submittedFields != null) {
            fields.putAll(submittedFields);
        }
        putIfPresent(fields, "firstName", firstName);
        putIfPresent(fields, "lastName", lastName);
        if (userId == null) {
            userId = createApplicationUserInKeycloak(
                    token,
                    keycloakUsername,
                    externalUsername,
                    password,
                    temporaryPassword,
                    sendPasswordSetupEmail,
                    email,
                    organizationId,
                    applicationId,
                    clientId,
                    fields);
        } else {
            updateApplicationUserSetup(
                    token,
                    userId,
                    keycloakUsername,
                    externalUsername,
                    email,
                    organizationId,
                    applicationId,
                    clientId,
                    fields,
                    sendPasswordSetupEmail);
            if (!sendPasswordSetupEmail && password != null && !password.isBlank()) {
                resetApplicationUserPassword(token, userId, password, temporaryPassword);
            }
        }
        joinGroup(token, userId, usersGroupId);
        String normalizedRole = "APPLICATION_SUPER_ADMIN".equalsIgnoreCase(roleName)
                ? "APPLICATION_SUPER_ADMIN"
                : "APPLICATION_USER";
        assignRealmRole(token, userId, normalizedRole, "Migrated Identity OS user");
        if ("APPLICATION_SUPER_ADMIN".equals(normalizedRole)) {
            assignApplicationUserRole(token, userId);
        }
        if (sendPasswordSetupEmail) {
            if (email == null || email.isBlank()) {
                throw new IllegalArgumentException("Email is required to send password setup link for migrated user.");
            }
            sendPasswordSetupEmail(token, userId);
        }
        return userId;
    }

    public void completeApplicationUserSetup(String keycloakUsername, String externalUsername, String password) {
        String token = requestAdminToken();
        String userId = findUserIdByUsername(token, keycloakUsername);
        if (userId == null) {
            return;
        }
        JsonNode existingUser = getUser(token, userId);
        Map<String, Object> user = new LinkedHashMap<>();
        user.put("username", keycloakUsername);
        user.put("enabled", true);
        user.put("emailVerified", true);
        user.put("requiredActions", List.of());
        if (existingUser != null) {
            putIfJsonPresent(user, "id", existingUser.get("id"));
            putIfJsonPresent(user, "email", existingUser.get("email"));
            putIfJsonPresent(user, "firstName", existingUser.get("firstName"));
            putIfJsonPresent(user, "lastName", existingUser.get("lastName"));
            if (existingUser.has("attributes") && !existingUser.get("attributes").isNull()) {
                user.put("attributes", existingUser.get("attributes"));
            }
            if (existingUser.has("groups") && !existingUser.get("groups").isNull()) {
                user.put("groups", existingUser.get("groups"));
            }
        }
        user.putIfAbsent("firstName", profileFirstName(externalUsername));
        user.putIfAbsent("lastName", profileLastName());
        restClient.put()
                .uri("/admin/realms/" + targetRealm + "/users/" + userId)
                .headers(headers -> headers.setBearerAuth(token))
                .contentType(MediaType.APPLICATION_JSON)
                .body(user)
                .retrieve()
                .toBodilessEntity();
        resetApplicationUserPassword(token, userId, password);
    }

    public JsonNode authenticateApplicationUser(String keycloakUsername, String password) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "password");
        form.add("client_id", userClientId);
        form.add("username", keycloakUsername);
        form.add("password", password);

        JsonNode response = restClient.post()
                .uri("/realms/" + targetRealm + "/protocol/openid-connect/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form)
                .retrieve()
                .body(JsonNode.class);
        if (response == null || response.get("access_token") == null) {
            throw new IllegalStateException("Keycloak token was not returned");
        }
        return response;
    }

    /** Creates/updates only integration-owned clients; never changes another application's client. */
    public Map<String,Object> provisionIntegrationClient(String applicationId, String organizationId,
            com.identityos.onboarding_and_identity_service.integration.IntegrationConfiguration config) {
        String token=requestAdminToken();
        String oidcId="identityos-"+applicationId;
        String uuid=upsertIntegrationClient(token,oidcId,applicationId,organizationId,config,false);
        String serviceUuid=upsertIntegrationClient(token,oidcId+"-service",applicationId,organizationId,config,true);
        return Map.of("clientId",oidcId,"keycloakClientUuid",uuid,"serviceClientId",oidcId+"-service",
                "serviceClientUuid",serviceUuid);
    }

    public Map<String,Object> integrationCredentials(String applicationId,
            com.identityos.onboarding_and_identity_service.integration.IntegrationConfiguration config) {
        String token=requestAdminToken();
        Map<String,Object> result=new LinkedHashMap<>();
        for(String id:List.of("identityos-"+applicationId,"identityos-"+applicationId+"-service")) {
            JsonNode client=findIntegrationClient(token,id);
            if(client==null || !applicationId.equals(client.path("attributes").path("identityos.application_id").asText()))
                throw new IllegalStateException("Integration client has not been provisioned");
            if(!client.path("publicClient").asBoolean()) {
                JsonNode secret=restClient.get().uri("/admin/realms/"+targetRealm+"/clients/"+client.path("id").asText()+"/client-secret")
                    .headers(h->h.setBearerAuth(token)).retrieve().body(JsonNode.class);
                result.put(id,secret.path("value").asText());
            }
        }
        return result;
    }

    public void setIntegrationClientsEnabled(String applicationId,boolean enabled) {
        String token=requestAdminToken();
        for(String id:List.of("identityos-"+applicationId,"identityos-"+applicationId+"-service")) {
            JsonNode client=findIntegrationClient(token,id);
            if(client!=null && applicationId.equals(client.path("attributes").path("identityos.application_id").asText()))
                restClient.put().uri("/admin/realms/"+targetRealm+"/clients/"+client.path("id").asText())
                    .headers(h->h.setBearerAuth(token)).body(Map.of("enabled",enabled)).retrieve().toBodilessEntity();
        }
    }

    private JsonNode findIntegrationClient(String token,String id) {
        JsonNode clients=restClient.get().uri(b->b.path("/admin/realms/"+targetRealm+"/clients").queryParam("clientId",id).build())
            .headers(h->h.setBearerAuth(token)).retrieve().body(JsonNode.class);
        return clients!=null && !clients.isEmpty()?clients.get(0):null;
    }

    private String upsertIntegrationClient(String token,String id,String app,String org,
            com.identityos.onboarding_and_identity_service.integration.IntegrationConfiguration config,boolean machine) {
        JsonNode existing=findIntegrationClient(token,id);
        if(existing!=null && !app.equals(existing.path("attributes").path("identityos.application_id").asText()))
            throw new IllegalStateException("Client ID is already owned by another integration");
        Map<String,Object> body=new LinkedHashMap<>();
        body.put("clientId",id);body.put("enabled",true);body.put("protocol","openid-connect");
        body.put("publicClient",!machine && "public".equals(config.clientType()));
        body.put("standardFlowEnabled",!machine);body.put("implicitFlowEnabled",false);
        body.put("directAccessGrantsEnabled",false);body.put("serviceAccountsEnabled",machine);
        body.put("fullScopeAllowed",false);
        body.put("redirectUris",machine?List.of():config.redirectUris());
        body.put("webOrigins",machine?List.of():config.webOrigins());
        List<String> clientScopes=new java.util.ArrayList<>(List.of("profile","email","roles","basic"));
        if(machine) for(String scope:List.of("identityos:authorize","identityos:consent","identityos:audit")) {
            ensureIntegrationScope(token,scope);clientScopes.add(scope);
        }
        if(!machine) for(String scope:config.scopes()) {
            if(!List.of("openid","profile","email","roles","basic").contains(scope)) {
                ensureIntegrationScope(token,scope);clientScopes.add(scope);
            }
        }
        body.put("defaultClientScopes",clientScopes);
        body.put("optionalClientScopes",List.of());
        body.put("attributes",Map.of("identityos.application_id",app,"pkce.code.challenge.method","S256",
            "post.logout.redirect.uris",String.join("##",config.postLogoutRedirectUris())));
        List<Map<String,Object>> mappers=new java.util.ArrayList<>();
        mappers.add(hardcodedClaim("organization_id",org));mappers.add(hardcodedClaim("application_id",app));
        mappers.add(audienceMapper("identity-os-integration"));
        if(machine) {
            mappers.add(audienceMapper("identity-os-services"));
        } else {
            mappers.add(audienceMapper(app));
            mappers.add(Map.of("name","external username","protocol","openid-connect","protocolMapper","oidc-usermodel-attribute-mapper",
                "config",Map.of("user.attribute","external_username","claim.name","external_username","jsonType.label","String",
                    "access.token.claim","true","id.token.claim","true","userinfo.token.claim","true")));
        }
        body.put("protocolMappers",mappers);
        if(existing==null) {
            try { restClient.post().uri("/admin/realms/"+targetRealm+"/clients").headers(h->h.setBearerAuth(token))
                .contentType(MediaType.APPLICATION_JSON).body(body).retrieve().toBodilessEntity(); }
            catch(HttpClientErrorException.Conflict race) { /* Re-read and verify ownership on retry. */ }
            existing=findIntegrationClient(token,id);
            if(existing==null || !app.equals(existing.path("attributes").path("identityos.application_id").asText()))
                throw new IllegalStateException("Client provisioning conflict");
        } else {
            restClient.put().uri("/admin/realms/"+targetRealm+"/clients/"+existing.path("id").asText())
                .headers(h->h.setBearerAuth(token)).contentType(MediaType.APPLICATION_JSON).body(body).retrieve().toBodilessEntity();
        }
        String uuid=existing.path("id").asText();
        JsonNode optionalScopes=restClient.get().uri("/admin/realms/"+targetRealm+"/clients/"+uuid+"/optional-client-scopes")
            .headers(h->h.setBearerAuth(token)).retrieve().body(JsonNode.class);
        for(JsonNode scope:optionalScopes) restClient.delete()
            .uri("/admin/realms/"+targetRealm+"/clients/"+uuid+"/optional-client-scopes/"+scope.path("id").asText())
            .headers(h->h.setBearerAuth(token)).retrieve().toBodilessEntity();
        JsonNode currentScopes=restClient.get().uri("/admin/realms/"+targetRealm+"/clients/"+uuid+"/default-client-scopes")
            .headers(h->h.setBearerAuth(token)).retrieve().body(JsonNode.class);
        for(JsonNode scope:currentScopes) if(!clientScopes.contains(scope.path("name").asText())) {
            restClient.delete().uri("/admin/realms/"+targetRealm+"/clients/"+uuid+"/default-client-scopes/"+scope.path("id").asText())
                .headers(h->h.setBearerAuth(token)).retrieve().toBodilessEntity();
        }
        JsonNode availableScopes=restClient.get().uri("/admin/realms/"+targetRealm+"/client-scopes")
            .headers(h->h.setBearerAuth(token)).retrieve().body(JsonNode.class);
        for(JsonNode scope:availableScopes) if(clientScopes.contains(scope.path("name").asText())) {
            restClient.put().uri("/admin/realms/"+targetRealm+"/clients/"+uuid+"/default-client-scopes/"+scope.path("id").asText())
                .headers(h->h.setBearerAuth(token)).retrieve().toBodilessEntity();
        }
        if(!machine) {
            Set<String> allowed=new java.util.HashSet<>(List.of("APPLICATION_USER","APPLICATION_SUPER_ADMIN"));
            allowed.addAll(config.roleMappings().keySet());
            JsonNode currentRoles=restClient.get().uri("/admin/realms/"+targetRealm+"/clients/"+uuid+"/scope-mappings/realm")
                .headers(h->h.setBearerAuth(token)).retrieve().body(JsonNode.class);
            List<JsonNode> removedRoles=new ArrayList<>();
            for(JsonNode role:currentRoles) if(!allowed.contains(role.path("name").asText())) removedRoles.add(role);
            if(!removedRoles.isEmpty()) restClient.method(HttpMethod.DELETE)
                .uri("/admin/realms/"+targetRealm+"/clients/"+uuid+"/scope-mappings/realm")
                .headers(h->h.setBearerAuth(token)).body(removedRoles).retrieve().toBodilessEntity();
            for(String role:allowed) {
                try { JsonNode representation=getRealmRole(token,role);
                    restClient.post().uri("/admin/realms/"+targetRealm+"/clients/"+uuid+"/scope-mappings/realm")
                        .headers(h->h.setBearerAuth(token)).body(List.of(representation)).retrieve().toBodilessEntity();
                } catch(HttpClientErrorException.NotFound absent) { /* Optional source role has not been defined. */ }
            }
        }
        return uuid;
    }

    private void ensureIntegrationScope(String token,String scope) {
        JsonNode scopes=restClient.get().uri("/admin/realms/"+targetRealm+"/client-scopes")
            .headers(h->h.setBearerAuth(token)).retrieve().body(JsonNode.class);
        for(JsonNode existing:scopes) if(scope.equals(existing.path("name").asText())) {
            if(!"openid-connect".equals(existing.path("protocol").asText())) throw new IllegalStateException("Scope protocol conflict");
            return;
        }
        try { restClient.post().uri("/admin/realms/"+targetRealm+"/client-scopes").headers(h->h.setBearerAuth(token))
            .body(Map.of("name",scope,"protocol","openid-connect","attributes",Map.of("include.in.token.scope","true")))
            .retrieve().toBodilessEntity(); }
        catch(HttpClientErrorException.Conflict race) { /* Another provisioning request created the same scope. */ }
    }

    private Map<String,Object> hardcodedClaim(String name,String value) {
        return Map.of("name","identityos-"+name,"protocol","openid-connect","protocolMapper","oidc-hardcoded-claim-mapper",
            "config",Map.of("claim.name",name,"claim.value",value,"jsonType.label","String",
                "access.token.claim","true","id.token.claim","false","userinfo.token.claim","false"));
    }
    private Map<String,Object> audienceMapper(String audience) {
        return Map.of("name","identityos-audience-"+audience,"protocol","openid-connect","protocolMapper","oidc-audience-mapper",
            "config",Map.of("included.custom.audience",audience,"access.token.claim","true","id.token.claim","false"));
    }

    private String requestAdminToken() {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("client_id", clientId);
        if (adminClientSecret != null && !adminClientSecret.isBlank()) {
            form.add("grant_type", "client_credentials");
            form.add("client_secret", adminClientSecret);
        } else {
            form.add("grant_type", "password");
            form.add("username", username);
            form.add("password", password);
        }

        JsonNode response = restClient.post()
            .uri("/realms/" + adminRealm + "/protocol/openid-connect/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .body(form)
                .retrieve()
                .body(JsonNode.class);
        if (response == null || response.get("access_token") == null) {
            throw new IllegalStateException("Keycloak admin token was not returned");
        }
        return response.get("access_token").asText();
    }

    private String createUser(String token, String organizationId, String representativeName, String email) {
        String[] nameParts = representativeName.trim().split("\\s+", 2);
        Map<String, Object> user = Map.of(
                "username", organizationId,
                "email", email,
                "emailVerified", true,
                "enabled", true,
                "firstName", nameParts[0],
                "lastName", nameParts.length > 1 ? nameParts[1] : "",
                "attributes", Map.of("organization_id", List.of(organizationId)),
                "credentials", List.of(Map.of(
                    "type", "password",
                    "value", organizationId,
                    "temporary", true)),
                "requiredActions", List.of("UPDATE_PASSWORD"));

        var response = restClient.post()
                .uri("/admin/realms/" + targetRealm + "/users")
                .headers(headers -> headers.setBearerAuth(token))
                .contentType(MediaType.APPLICATION_JSON)
                .body(user)
                .retrieve()
                .toBodilessEntity();
        String location = response.getHeaders().getFirst("Location");
        if (location == null || location.isBlank()) {
            throw new IllegalStateException("Keycloak did not return the created user location");
        }
        return location.substring(location.lastIndexOf('/') + 1);
    }

    private String createSelfHostedAdminUser(
            String token,
            String adminUsername,
            String displayName,
            String email,
            String password,
            String organizationId,
            String applicationId,
            String clientId) {
        String[] nameParts = displayName.trim().isBlank()
                ? new String[] {adminUsername}
                : displayName.trim().split("\\s+", 2);
        Map<String, Object> user = new LinkedHashMap<>();
        user.put("username", adminUsername);
        user.put("enabled", true);
        user.put("emailVerified", true);
        user.put("firstName", nameParts[0]);
        user.put("lastName", nameParts.length > 1 ? nameParts[1] : "Admin");
        if (email != null && !email.isBlank()) {
            user.put("email", email);
        }
        user.put("attributes", Map.of(
                "organization_id", List.of(organizationId),
                "application_id", List.of(applicationId),
                "client_id", List.of(clientId),
                "external_username", List.of(adminUsername)));
        user.put("requiredActions", List.of());
        if (password != null && !password.isBlank()) {
            user.put("credentials", List.of(Map.of(
                    "type", "password",
                    "value", password,
                    "temporary", false)));
        }

        var response = restClient.post()
                .uri("/admin/realms/" + targetRealm + "/users")
                .headers(headers -> headers.setBearerAuth(token))
                .contentType(MediaType.APPLICATION_JSON)
                .body(user)
                .retrieve()
                .toBodilessEntity();
        String location = response.getHeaders().getFirst("Location");
        if (location == null || location.isBlank()) {
            throw new IllegalStateException("Keycloak did not return the created user location");
        }
        return location.substring(location.lastIndexOf('/') + 1);
    }

    private void updateSelfHostedAdminUser(
            String token,
            String userId,
            String adminUsername,
            String displayName,
            String email,
            String organizationId,
            String applicationId,
            String clientId) {
        String[] nameParts = displayName.trim().isBlank()
                ? new String[] {adminUsername}
                : displayName.trim().split("\\s+", 2);
        Map<String, Object> user = new LinkedHashMap<>();
        user.put("username", adminUsername);
        user.put("enabled", true);
        user.put("emailVerified", true);
        user.put("firstName", nameParts[0]);
        user.put("lastName", nameParts.length > 1 ? nameParts[1] : "Admin");
        if (email != null && !email.isBlank()) {
            user.put("email", email);
        }
        user.put("attributes", Map.of(
                "organization_id", List.of(organizationId),
                "application_id", List.of(applicationId),
                "client_id", List.of(clientId),
                "external_username", List.of(adminUsername)));
        user.put("requiredActions", List.of());

        restClient.put()
                .uri("/admin/realms/" + targetRealm + "/users/" + userId)
                .headers(headers -> headers.setBearerAuth(token))
                .contentType(MediaType.APPLICATION_JSON)
                .body(user)
                .retrieve()
                .toBodilessEntity();
    }

    private String findUserIdByUsername(String token, String username) {
        JsonNode users = restClient.get()
                .uri(uriBuilder -> uriBuilder
                        .path("/admin/realms/" + targetRealm + "/users")
                        .queryParam("username", username)
                        .queryParam("exact", true)
                        .build())
                .headers(headers -> headers.setBearerAuth(token))
                .retrieve()
                .body(JsonNode.class);
        if (users == null || !users.isArray() || users.isEmpty()) {
            return null;
        }
        return users.get(0).get("id").asText();
    }

    private JsonNode getUser(String token, String userId) {
        return restClient.get()
                .uri("/admin/realms/" + targetRealm + "/users/" + userId)
                .headers(headers -> headers.setBearerAuth(token))
                .retrieve()
                .body(JsonNode.class);
    }

    private void updateUser(String token, String userId, String organizationId, String representativeName, String email) {
        String[] nameParts = representativeName.trim().split("\\s+", 2);
        restClient.put()
                .uri("/admin/realms/" + targetRealm + "/users/" + userId)
                .headers(headers -> headers.setBearerAuth(token))
                .contentType(MediaType.APPLICATION_JSON)
                .body(Map.of(
                    "username", organizationId,
                    "email", email,
                    "emailVerified", true,
                    "enabled", true,
                    "firstName", nameParts[0],
                    "lastName", nameParts.length > 1 ? nameParts[1] : "",
                    "attributes", Map.of("organization_id", List.of(organizationId))))
                .retrieve()
                .toBodilessEntity();
    }

    private void assignOrganizationAdminRole(String token, String userId) {
        JsonNode role;
        try {
            role = getOrganizationAdminRole(token);
        } catch (HttpClientErrorException.NotFound exception) {
            restClient.post()
                .uri("/admin/realms/" + targetRealm + "/roles")
                .headers(headers -> headers.setBearerAuth(token))
                .contentType(MediaType.APPLICATION_JSON)
                .body(Map.of(
                    "name", "ORGANISATION_ADMIN",
                    "description", "Administrator for a single organization"))
                .retrieve()
                .toBodilessEntity();
            role = getOrganizationAdminRole(token);
        }
        try {
            restClient.post()
                .uri("/admin/realms/" + targetRealm + "/users/" + userId + "/role-mappings/realm")
                .headers(headers -> headers.setBearerAuth(token))
                .contentType(MediaType.APPLICATION_JSON)
                .body(List.of(role))
                .retrieve()
                .toBodilessEntity();
        } catch (HttpClientErrorException.Conflict exception) {
            // Role mapping is already present; the desired state is satisfied.
        }
    }

    private JsonNode getOrganizationAdminRole(String token) {
        return restClient.get()
                .uri("/admin/realms/" + targetRealm + "/roles/ORGANISATION_ADMIN")
                .headers(headers -> headers.setBearerAuth(token))
                .retrieve()
                .body(JsonNode.class);
    }

    private void assignApplicationUserRole(String token, String userId) {
        assignRealmRole(token, userId, "APPLICATION_USER", "End user registered through a third-party application");
    }

    private void assignRealmRole(String token, String userId, String roleName, String description) {
        JsonNode role;
        try {
            role = getRealmRole(token, roleName);
        } catch (HttpClientErrorException.NotFound exception) {
            restClient.post()
                .uri("/admin/realms/" + targetRealm + "/roles")
                .headers(headers -> headers.setBearerAuth(token))
                .contentType(MediaType.APPLICATION_JSON)
                .body(Map.of(
                    "name", roleName,
                    "description", description))
                .retrieve()
                .toBodilessEntity();
            role = getRealmRole(token, roleName);
        }
        try {
            restClient.post()
                .uri("/admin/realms/" + targetRealm + "/users/" + userId + "/role-mappings/realm")
                .headers(headers -> headers.setBearerAuth(token))
                .contentType(MediaType.APPLICATION_JSON)
                .body(List.of(role))
                .retrieve()
                .toBodilessEntity();
        } catch (HttpClientErrorException.Conflict exception) {
            // Role mapping is already present; the desired state is satisfied.
        }
    }

    private JsonNode getRealmRole(String token, String roleName) {
        return restClient.get()
                .uri("/admin/realms/" + targetRealm + "/roles/" + roleName)
                .headers(headers -> headers.setBearerAuth(token))
                .retrieve()
                .body(JsonNode.class);
    }

    private String createApplicationUserInKeycloak(
            String token,
            String keycloakUsername,
            String externalUsername,
            String password,
            String email,
            String organizationId,
            String applicationId,
            String clientId,
            Map<String, Object> submittedFields) {
        return createApplicationUserInKeycloak(
                token,
                keycloakUsername,
                externalUsername,
                password,
                false,
                false,
                email,
                organizationId,
                applicationId,
                clientId,
                submittedFields);
    }

    private String createApplicationUserInKeycloak(
            String token,
            String keycloakUsername,
            String externalUsername,
            String password,
            boolean temporaryPassword,
            boolean passwordSetupRequired,
            String email,
            String organizationId,
            String applicationId,
            String clientId,
            Map<String, Object> submittedFields) {
        Map<String, Object> user = new LinkedHashMap<>();
        user.put("username", keycloakUsername);
        user.put("enabled", true);
        user.put("emailVerified", true);
        user.put("requiredActions", passwordSetupRequired ? List.of("UPDATE_PASSWORD") : List.of());
        if (email != null && !email.isBlank()) {
            user.put("email", email);
        }
        putIfPresent(user, "firstName", submittedFields.get("firstName"));
        putIfPresent(user, "lastName", submittedFields.get("lastName"));
        user.putIfAbsent("firstName", profileFirstName(externalUsername));
        user.putIfAbsent("lastName", profileLastName());
        Map<String,List<String>> identityAttributes = new LinkedHashMap<>(Map.of(
                "organization_id", List.of(organizationId),
                "application_id", List.of(applicationId),
                "client_id", List.of(clientId),
                "external_username", List.of(externalUsername)));
        Object externalId = submittedFields.get("external_user_id");
        if (externalId != null && !externalId.toString().isBlank()) identityAttributes.put("external_user_id", List.of(externalId.toString()));
        user.put("attributes", identityAttributes);
        if (password != null && !password.isBlank()) {
            user.put("credentials", List.of(Map.of(
                    "type", "password",
                    "value", password,
                    "temporary", temporaryPassword)));
        }

        var response = restClient.post()
                .uri("/admin/realms/" + targetRealm + "/users")
                .headers(headers -> headers.setBearerAuth(token))
                .contentType(MediaType.APPLICATION_JSON)
                .body(user)
                .retrieve()
                .toBodilessEntity();
        String location = response.getHeaders().getFirst("Location");
        if (location == null || location.isBlank()) {
            throw new IllegalStateException("Keycloak did not return the created user location");
        }
        return location.substring(location.lastIndexOf('/') + 1);
    }

    private void updateApplicationUserSetup(
            String token,
            String userId,
            String keycloakUsername,
            String externalUsername,
            String email,
            String organizationId,
            String applicationId,
            String clientId,
            Map<String, Object> submittedFields) {
        updateApplicationUserSetup(
                token,
                userId,
                keycloakUsername,
                externalUsername,
                email,
                organizationId,
                applicationId,
                clientId,
                submittedFields,
                false);
    }

    private void updateApplicationUserSetup(
            String token,
            String userId,
            String keycloakUsername,
            String externalUsername,
            String email,
            String organizationId,
            String applicationId,
            String clientId,
            Map<String, Object> submittedFields,
            boolean passwordSetupRequired) {
        Map<String, Object> user = new LinkedHashMap<>();
        user.put("username", keycloakUsername);
        user.put("enabled", true);
        user.put("emailVerified", true);
        user.put("requiredActions", passwordSetupRequired ? List.of("UPDATE_PASSWORD") : List.of());
        if (email != null && !email.isBlank()) {
            user.put("email", email);
        }
        putIfPresent(user, "firstName", submittedFields.get("firstName"));
        putIfPresent(user, "lastName", submittedFields.get("lastName"));
        user.putIfAbsent("firstName", profileFirstName(externalUsername));
        user.putIfAbsent("lastName", profileLastName());
        user.put("attributes", Map.of(
                "organization_id", List.of(organizationId),
                "application_id", List.of(applicationId),
                "client_id", List.of(clientId),
                "external_username", List.of(externalUsername)));

        restClient.put()
                .uri("/admin/realms/" + targetRealm + "/users/" + userId)
                .headers(headers -> headers.setBearerAuth(token))
                .contentType(MediaType.APPLICATION_JSON)
                .body(user)
                .retrieve()
                .toBodilessEntity();
    }

    private void resetApplicationUserPassword(String token, String userId, String password) {
        resetApplicationUserPassword(token, userId, password, false);
    }

    private void resetApplicationUserPassword(String token, String userId, String password, boolean temporaryPassword) {
        restClient.put()
                .uri("/admin/realms/" + targetRealm + "/users/" + userId + "/reset-password")
                .headers(headers -> headers.setBearerAuth(token))
                .contentType(MediaType.APPLICATION_JSON)
                .body(Map.of(
                        "type", "password",
                        "value", password,
                        "temporary", temporaryPassword))
                .retrieve()
                .toBodilessEntity();
    }

    private void putIfPresent(Map<String, Object> target, String key, Object value) {
        if (value != null && !String.valueOf(value).isBlank()) {
            target.put(key, String.valueOf(value));
        }
    }

    private void putIfJsonPresent(Map<String, Object> target, String key, JsonNode value) {
        if (value != null && !value.isNull() && !value.asText("").isBlank()) {
            target.put(key, value.asText());
        }
    }

    private String profileFirstName(String externalUsername) {
        String value = externalUsername == null ? "" : externalUsername.trim();
        int emailSeparator = value.indexOf('@');
        if (emailSeparator > 0) {
            value = value.substring(0, emailSeparator);
        }
        value = value.replaceAll("[^A-Za-z0-9 -]", " ").trim();
        return value.isBlank() ? "Application" : value;
    }

    private String profileLastName() {
        return "User";
    }

    private String ensureGroupHierarchy(String token, String organizationId, String applicationId) {
        String organizationGroupId = ensureRootGroup(token, organizationId);
        String applicationGroupId = ensureChildGroup(token, organizationGroupId, applicationId);
        return ensureChildGroup(token, applicationGroupId, "users");
    }

    private String ensureRootGroup(String token, String groupName) {
        String groupId = findRootGroupId(token, groupName);
        if (groupId != null) {
            return groupId;
        }
        restClient.post()
                .uri("/admin/realms/" + targetRealm + "/groups")
                .headers(headers -> headers.setBearerAuth(token))
                .contentType(MediaType.APPLICATION_JSON)
                .body(Map.of("name", groupName))
                .retrieve()
                .toBodilessEntity();
        groupId = findRootGroupId(token, groupName);
        if (groupId == null) {
            throw new IllegalStateException("Keycloak group was not created: " + groupName);
        }
        return groupId;
    }

    private String ensureChildGroup(String token, String parentGroupId, String groupName) {
        String groupId = findChildGroupId(token, parentGroupId, groupName);
        if (groupId != null) {
            return groupId;
        }
        restClient.post()
                .uri("/admin/realms/" + targetRealm + "/groups/" + parentGroupId + "/children")
                .headers(headers -> headers.setBearerAuth(token))
                .contentType(MediaType.APPLICATION_JSON)
                .body(Map.of("name", groupName))
                .retrieve()
                .toBodilessEntity();
        groupId = findChildGroupId(token, parentGroupId, groupName);
        if (groupId == null) {
            throw new IllegalStateException("Keycloak child group was not created: " + groupName);
        }
        return groupId;
    }

    private String findRootGroupId(String token, String groupName) {
        JsonNode groups = restClient.get()
                .uri(uriBuilder -> uriBuilder
                        .path("/admin/realms/" + targetRealm + "/groups")
                        .queryParam("search", groupName)
                        .build())
                .headers(headers -> headers.setBearerAuth(token))
                .retrieve()
                .body(JsonNode.class);
        return findGroupIdByName(groups, groupName);
    }

    private String findChildGroupId(String token, String parentGroupId, String groupName) {
        JsonNode groups = restClient.get()
                .uri(uriBuilder -> uriBuilder
                        .path("/admin/realms/" + targetRealm + "/groups/" + parentGroupId + "/children")
                        .queryParam("search", groupName)
                        .build())
                .headers(headers -> headers.setBearerAuth(token))
                .retrieve()
                .body(JsonNode.class);
        return findGroupIdByName(groups, groupName);
    }

    private String findGroupIdByName(JsonNode groups, String groupName) {
        if (groups == null || !groups.isArray()) {
            return null;
        }
        for (JsonNode group : groups) {
            if (groupName.equals(group.path("name").asText())) {
                return group.path("id").asText();
            }
        }
        return null;
    }

    private void joinGroup(String token, String userId, String groupId) {
        restClient.put()
                .uri("/admin/realms/" + targetRealm + "/users/" + userId + "/groups/" + groupId)
                .headers(headers -> headers.setBearerAuth(token))
                .retrieve()
                .toBodilessEntity();
    }

    private void sendVerificationEmail(String token, String userId) {
        sendPasswordSetupEmail(token, userId);
    }

    private void sendPasswordSetupEmail(String token, String userId) {
        restClient.put()
                .uri("/admin/realms/" + targetRealm + "/users/" + userId + "/execute-actions-email")
                .headers(headers -> headers.setBearerAuth(token))
                .contentType(MediaType.APPLICATION_JSON)
                .body(List.of("UPDATE_PASSWORD"))
                .retrieve()
                .toBodilessEntity();
    }

    private void deleteUser(String token, String userId) {
        restClient.delete()
                .uri("/admin/realms/" + targetRealm + "/users/" + userId)
                .headers(headers -> headers.setBearerAuth(token))
                .retrieve()
                .toBodilessEntity();
    }
}
