package org.jasig.cas.client.tomcat.v90;

import java.io.IOException;
import java.security.Principal;

import org.apache.catalina.Context;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.tomcat.util.descriptor.web.SecurityCollection;
import org.apache.tomcat.util.descriptor.web.SecurityConstraint;
import org.jasig.cas.client.tomcat.common.SecurityInjector;
import org.jasig.cas.client.tomcat.common.TomcatRealmProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MappedAssertionCasRealm extends AssertionCasRealm implements
        TomcatRealmProvider<SecurityConstraint, Context, Request, Response> {

    private static final Logger logger = LoggerFactory.getLogger(MappedAssertionCasRealm.class);

    private final SecurityInjector<SecurityConstraint, Context, Request, Response> securityprocessor;

    public MappedAssertionCasRealm() {
        securityprocessor = new SecurityInjector<>(logger, this);
    }

    public void setMappingProperties(String propFile) {
        securityprocessor.setMappingProperties(propFile);
    }

    @Override
    public String[] getRoles(Principal principal) {
        return securityprocessor.getRoles(principal);
    }

    @Override
    public SecurityConstraint[] newSecurityContext(int i) {
        return new SecurityConstraint[i];
    }

    @Override
    public SecurityConstraint buildConstraint(boolean restricted, String pattern) {
        SecurityConstraint constraint = new SecurityConstraint();
        SecurityCollection sc = new SecurityCollection();
        sc.setName(pattern);
        sc.addPattern(pattern);
        constraint.addCollection(sc);
        constraint.setAuthConstraint(restricted);
        constraint.setDisplayName(pattern);
        if (restricted) {
            constraint.addAuthRole(SecurityConstraint.ROLE_ALL_ROLES);
            constraint.addAuthRole(SecurityConstraint.ROLE_ALL_AUTHENTICATED_USERS);
        }
        return constraint;
    }

    @Override
    public void addSecurityRole(String role, Context context) {
        context.addSecurityRole(role);
    }

    @Override
    public boolean isIncluded(SecurityConstraint constraint, String uri, String method) {
        return constraint.included(uri, method);
    }

    @Override
    public boolean hasRole(Principal principal, String role) {
        return securityprocessor.hasRole(principal, role);
    }

    @Override
    public SecurityConstraint[] findSecurityConstraints(Request request,
            Context ctx) {
        return securityprocessor.findSecurityConstraints(request, ctx);
    }

    @Override
    public boolean superHasResourcePermission(Request request, Response response, SecurityConstraint[] constraints,
            Context context) throws IOException {
        return super.hasResourcePermission(request, response, constraints, context);
    }

    @Override
    public boolean superHasUserDataPermission(Request request, Response response, SecurityConstraint[] constraints)
            throws IOException {
        return super.hasUserDataPermission(request, response, constraints);
    }

    @Override
    public boolean superHasRole(Principal principal, String role) {
        return super.hasRole(principal, role);
    }

    @Override
    public SecurityConstraint[] superFindSecurityConstraints(Request request, Context ctx) {
        return super.findSecurityConstraints(request, ctx);
    }

    @Override
    public boolean hasResourcePermission(Request request, Response response,
            SecurityConstraint[] constraints, Context context) throws IOException {
        return securityprocessor.hasResourcePermission(request, response, constraints, context, request.getPrincipal());
    }

    @Override
    public boolean hasUserDataPermission(Request request, Response response,
            SecurityConstraint[] constraints) throws IOException {
        return securityprocessor.hasUserDataPermission(request, response, constraints, request.getPrincipal());
    }

    public void setOverrideSecurity(boolean overrideSecurity) {
        securityprocessor.setOverrideSecurity(overrideSecurity);
    }

    public String getFilter() {
        return securityprocessor.getFilter();
    }

    public void setFilter(String filter) {
        securityprocessor.setFilter(filter);
    }

    public String getHeaderFilter() {
        return securityprocessor.getHeaderFilter();
    }

    public void setHeaderFilter(String headerFilter) {
        securityprocessor.setHeaderFilter(headerFilter);
    }

    public void setAccesslist(String accesslist) {
        securityprocessor.setAccesslist(accesslist);
    }
}
