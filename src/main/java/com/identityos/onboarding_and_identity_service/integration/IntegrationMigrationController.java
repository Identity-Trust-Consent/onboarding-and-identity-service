package com.identityos.onboarding_and_identity_service.integration;

import com.identityos.onboarding_and_identity_service.dto.*;
import com.identityos.onboarding_and_identity_service.service.IdentityUserMigrationService;
import jakarta.validation.Valid;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.http.*;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/v1/integration/applications/{applicationId}/migrations")
public class IntegrationMigrationController {
  private final IntegrationService integrations;
  private final IntegrationRepository registry;
  private final IdentityUserMigrationService migration;
  public IntegrationMigrationController(IntegrationService integrations,IntegrationRepository registry,IdentityUserMigrationService migration) {
    this.integrations=integrations;this.registry=registry;this.migration=migration;
  }
  @PostMapping("/validate") public Object validate(@PathVariable String applicationId,@AuthenticationPrincipal Jwt actor,
      @Valid @RequestBody UserMigrationRequest request) {
    IntegrationSecurity.admin(actor,integrations.application(applicationId).organizationId());
    var errors=errors(applicationId,request,actor);return Map.of("valid",errors.isEmpty(),"errors",errors,"records",request.users().size());
  }
  @PostMapping public Object migrate(@PathVariable String applicationId,@AuthenticationPrincipal Jwt actor,
      @RequestHeader("Idempotency-Key") String key,@Valid @RequestBody UserMigrationRequest request) {
    IntegrationSecurity.admin(actor,integrations.effective(applicationId).application().organizationId());
    if(!key.matches("[A-Za-z0-9_.:-]{8,100}")) throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Invalid Idempotency-Key");
    var errors=errors(applicationId,request,actor);
    if(!errors.isEmpty()) throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY,String.join("; ",errors));
    String hash=hash(registry.json(request));
    var db=registry.jdbc();
    try { db.update("insert into integration_migration_request(application_id,idempotency_key,request_hash,state,actor) values (?,?,?,'PROCESSING',?)",applicationId,key,hash,actor.getSubject()); }
    catch(DuplicateKeyException duplicate) {
      var old=db.queryForMap("select request_hash,state,response::text from integration_migration_request where application_id=? and idempotency_key=?",applicationId,key);
      if(!hash.equals(old.get("request_hash"))) throw new ResponseStatusException(HttpStatus.CONFLICT,"Idempotency key was used for another request");
      if(!"COMPLETED".equals(old.get("state"))) throw new ResponseStatusException(HttpStatus.CONFLICT,"Migration is in progress or needs operator reconciliation");
      try { return new com.fasterxml.jackson.databind.ObjectMapper().readTree(old.get("response").toString()); }
      catch(Exception impossible) { throw new IllegalStateException(impossible); }
    }
    var safe=new UserMigrationRequest(applicationId,null,true,true,actor.getSubject(),request.fileName(),request.users());
    var result=migration.migrateUsers(safe);
    db.update("update integration_migration_request set state='COMPLETED',response=?::jsonb where application_id=? and idempotency_key=?",registry.json(result),applicationId,key);
    registry.audit("INTEGRATION_USERS_MIGRATED",actor.getSubject(),integrations.application(applicationId).organizationId(),applicationId,
      Map.of("batchId",result.batchId(),"successCount",result.successCount(),"failedCount",result.failedCount()));
    return result;
  }
  @GetMapping("/{idempotencyKey}") public Object status(@PathVariable String applicationId,@PathVariable String idempotencyKey,@AuthenticationPrincipal Jwt actor) {
    IntegrationSecurity.admin(actor,integrations.application(applicationId).organizationId());
    var rows=registry.jdbc().queryForList("select state,response,created_at from integration_migration_request where application_id=? and idempotency_key=?",applicationId,idempotencyKey);
    if(rows.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND,"Migration not found");return rows.get(0);
  }
  private List<String> errors(String app,UserMigrationRequest request,Jwt actor) {
    List<String> errors=new ArrayList<>();
    if(!app.equals(request.applicationId())) errors.add("Application ID mismatch");
    if(request.users().size()>1000) errors.add("Maximum migration batch is 1000 users");
    if(request.defaultTemporaryPassword()!=null || request.users().stream().anyMatch(u->u.temporaryPassword()!=null)) errors.add("This endpoint uses password setup email; plaintext/hash credential import is not supported");
    Set<String> normalized=new HashSet<>(),externalIds=new HashSet<>();int row=0;
    for(var user:request.users()) {
      row++;String prefix="Row "+row+": ";
      String name=user.username().trim().replaceAll("[^A-Za-z0-9._@-]","_").toLowerCase(Locale.ROOT);
      if(!normalized.add(name)) errors.add(prefix+"normalized username collision");
      if(user.externalUserId()==null || user.externalUserId().isBlank() || !externalIds.add(user.externalUserId())) errors.add(prefix+"unique externalUserId required");
      if(user.email()==null || !user.email().matches("[^@\\s]+@[^@\\s]+\\.[^@\\s]+")) errors.add(prefix+"password setup email required");
      if(user.role()!=null && !Set.of("APPLICATION_USER","APPLICATION_SUPER_ADMIN").contains(user.role())) errors.add(prefix+"explicit supported role mapping required");
      if("APPLICATION_SUPER_ADMIN".equals(user.role()) && !IntegrationSecurity.roles(actor).contains("PLATFORM_ADMIN")) errors.add(prefix+"platform admin required for elevated role");
      if(user.status()!=null && !"ACTIVE".equals(user.status())) errors.add(prefix+"only active users may be imported; migrate disabled accounts through a reviewed lifecycle process");
      var conflicts=registry.jdbc().queryForList("select external_user_id from identity_users where application_public_id=? and lower(username)=lower(?)",app,user.username());
      if(conflicts.stream().anyMatch(c->!Objects.equals(c.get("external_user_id"),user.externalUserId()))) errors.add(prefix+"existing username belongs to another external identity");
    }
    return errors;
  }
  private String hash(String text) { try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8))); } catch(NoSuchAlgorithmException e) { throw new IllegalStateException(e); } }
}
