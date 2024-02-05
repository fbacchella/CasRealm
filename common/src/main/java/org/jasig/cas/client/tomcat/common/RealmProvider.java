package org.jasig.cas.client.tomcat.common;

import java.io.IOException;
import java.security.Principal;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public interface RealmProvider<SC, CT, RQ extends HttpServletRequest, RS extends HttpServletResponse> {
    SC[] findSecurityConstraints(RQ request, CT ctx);

    boolean superHasResourcePermission(RQ request, RS response, SC[] constraints, CT context)
            throws IOException;

    boolean superHasUserDataPermission(RQ request, RS response, SC[] constraints)
            throws IOException;

    boolean superHasRole(Principal principal, String role);

    SC[] superFindSecurityConstraints(RQ request, CT ctx);

    String[] getRoles(Principal principal);

    SC[] newSecurityContext(int i);

    SC buildConstraint(boolean restricted, String pattern);

    void addSecurityRole(String role, CT context);

    boolean isIncluded(SC constraint, String uri, String method);

}
