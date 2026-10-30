package com.identityos.onboarding_and_identity_service.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

@Repository
public class IntegrationRepository {
  private final JdbcTemplate jdbc;
  private final ObjectMapper mapper;
  public IntegrationRepository(JdbcTemplate jdbc,ObjectMapper mapper) { this.jdbc=jdbc;this.mapper=mapper; }
  public record Versioned(long version,IntegrationConfiguration configuration,Long provisionedVersion,Long provisionedOrganizationVersion) {}
  public Versioned read(String id,boolean organization) {
    String table=organization?"integration_organization_config":"integration_application_config";
    String key=organization?"organization_id":"application_id";
    var rows=jdbc.query("select version,configuration::text"+(organization?",null as provisioned_version,null as provisioned_organization_version":",provisioned_version,provisioned_organization_version")+" from "+table+" where "+key+"=?",
      (rs,n)->new Versioned(rs.getLong(1),decode(rs.getString(2)),(Long)rs.getObject(3),(Long)rs.getObject(4)),id);
    return rows.isEmpty()?new Versioned(0,null,null,null):rows.get(0);
  }
  public Versioned save(String id,boolean organization,long expected,IntegrationConfiguration config,String actor) {
    String table=organization?"integration_organization_config":"integration_application_config";
    String key=organization?"organization_id":"application_id";
    int count=expected==0 ? jdbc.update("insert into "+table+" ("+key+",configuration,updated_by) values (?,?::jsonb,?) on conflict do nothing",id,json(config),actor)
      :jdbc.update("update "+table+" set configuration=?::jsonb,version=version+1,updated_by=?,updated_at=now() where "+key+"=? and version=?",json(config),actor,id,expected);
    if(count!=1) throw new ResponseStatusException(HttpStatus.CONFLICT,"Configuration version changed; reload before retrying");
    return read(id,organization);
  }
  public void provisioned(String app,long version,long orgVersion,String uuid) {
    if(jdbc.update("update integration_application_config set provisioned_version=?,provisioned_organization_version=?,keycloak_client_uuid=? where application_id=? and version=?",version,orgVersion,uuid,app,version)!=1)
      throw new ResponseStatusException(HttpStatus.CONFLICT,"Configuration changed during provisioning; provision again");
  }
  public void audit(String action,String actor,String org,String app,Map<String,Object> details) {
    var event=new LinkedHashMap<String,Object>();
    String id=UUID.randomUUID().toString();event.put("primaryKey",id);event.put("origin","onboarding-and-identity-service");
    event.put("action",action);event.put("actorUserId",actor);event.put("organizationId",org);event.put("applicationId",app);
    event.put("status","SUCCESS");event.put("isoTime",java.time.Instant.now().toString());event.put("metadata",details);
    jdbc.update("insert into integration_audit_outbox(event_id,payload) values (?::uuid,?::jsonb)",id,json(event));
  }
  public Optional<Map<String,Object>> identity(String app,String subject) {
    var rows=jdbc.queryForList("select id,username,external_user_id,status from identity_users where application_public_id=? and keycloak_user_id=?",app,subject);
    if(rows.size()>1) throw new ResponseStatusException(HttpStatus.CONFLICT,"Ambiguous identity mapping");
    return rows.stream().findFirst();
  }
  public void link(String app,String oldIssuer,String oldSubject,String issuer,String subject,String actor) {
    var existing=jdbc.queryForList("select identity_issuer,identity_subject from integration_identity_link where application_id=? and legacy_issuer=? and legacy_subject=?",app,oldIssuer,oldSubject);
    if(!existing.isEmpty()) {
      if(issuer.equals(existing.get(0).get("identity_issuer")) && subject.equals(existing.get(0).get("identity_subject"))) return;
      throw new ResponseStatusException(HttpStatus.CONFLICT,"Legacy account is already linked");
    }
    jdbc.update("insert into integration_identity_link(application_id,legacy_issuer,legacy_subject,identity_issuer,identity_subject,linked_by) values (?,?,?,?,?,?)",app,oldIssuer,oldSubject,issuer,subject,actor);
  }
  public List<Map<String,Object>> links(String app,String subject) {
    return jdbc.queryForList("select legacy_issuer,legacy_subject,linked_at from integration_identity_link where application_id=? and identity_subject=?",app,subject);
  }
  public JdbcTemplate jdbc() { return jdbc; }
  public String json(Object value) { try { return mapper.writeValueAsString(value); } catch(Exception e) { throw new IllegalArgumentException("Invalid integration JSON"); } }
  private IntegrationConfiguration decode(String json) { try { return mapper.readValue(json,IntegrationConfiguration.class); } catch(Exception e) { throw new IllegalStateException("Invalid stored integration configuration",e); } }
}
