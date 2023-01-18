package com.company.test10.security;

import io.jmix.oidc.claimsmapper.BaseClaimsRolesMapper;
import io.jmix.security.role.ResourceRoleRepository;
import io.jmix.security.role.RowLevelRoleRepository;
import org.springframework.stereotype.Component;

import com.nimbusds.jose.shaded.json.JSONObject;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

@Component
public class MyClaimsRoleMapper extends BaseClaimsRolesMapper {

    public MyClaimsRoleMapper(ResourceRoleRepository resourceRoleRepository,
                              RowLevelRoleRepository rowLevelRoleRepository) {
        super(resourceRoleRepository, rowLevelRoleRepository);
    }

    @Override
    protected Collection<String> getResourceRolesCodes(Map<String, Object> claims) {
        Collection<String> jmixRoleCodes = new HashSet<>();
        JSONObject jsonObject = new JSONObject(claims);
        List<String> roles = (List<String>) jsonObject.get("/roles");
        if (roles != null && roles.contains("ROLE_ADMIN")) {
            jmixRoleCodes.add("system-full-access");
        }
        return jmixRoleCodes;
    }
}