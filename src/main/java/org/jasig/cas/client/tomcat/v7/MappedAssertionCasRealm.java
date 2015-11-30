package org.jasig.cas.client.tomcat.v7;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.Set;
import java.util.regex.Pattern;

import javax.servlet.http.HttpSession;

import org.apache.catalina.Context;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.deploy.SecurityCollection;
import org.apache.catalina.deploy.SecurityConstraint;
import org.jasig.cas.client.authentication.AttributePrincipal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MappedAssertionCasRealm extends AssertionCasRealm {

    private final class SecuritySetup {
        SecurityConstraint[] scs = null;

        // Construct a new SecurityCollection, that will
        // override the one given in the web.xml
        void configure(Context ctx) {
            scs = new SecurityConstraint[] {new SecurityConstraint()};
            SecurityCollection sc = new SecurityCollection();
            sc.addPattern("/*");
            scs[0].addCollection(sc);
            scs[0].setAuthConstraint(true);
            scs[0].addAuthRole("*");
            for(String role: MappedAssertionCasRealm.this.roleMapping2.keySet()) {
                ctx.addSecurityRole(role);                
            }
        }
    }

    private final static Logger logger = LoggerFactory.getLogger(MappedAssertionCasRealm.class);

    private final SecuritySetup security = new SecuritySetup();

    // Map CAS group to one or many servlet role
    private final Map<String, Set<String>> roleMapping1 = new HashMap<>();
    // Map a servlet role to a CAS group
    private final Map<String, String> roleMapping2 = new HashMap<>();

    //Map a CAS attribute to a session attribute
    private final Map<String, String> attributeMapping = new HashMap<>();

    //Filter for direct access
    private Pattern filter = null;
    private String headerFilter = null;

    private boolean overrideSecurity = true;

    public void setMappingProperties(String propFile) {
        Properties prop = new Properties();
        try {
            prop.load(new FileReader(propFile));
        } catch (FileNotFoundException e) {
            throw new RuntimeException("file " + propFile + " not found ", e);
        } catch (IOException e) {
            throw new RuntimeException("file " + propFile + " can't be read ", e);
        }
        for(Entry<Object, Object> e: prop.entrySet()) {
            String key = e.getKey().toString();
            //If property is role.*, it maps the group name
            if(key.startsWith("role.")) {
                String servletGroup = key.replaceFirst("^role\\.", "");
                String casGroup = e.getValue().toString();
                if(! roleMapping1.containsKey(casGroup)) {
                    roleMapping1.put(casGroup, new HashSet<String>());
                }
                roleMapping1.get(casGroup).add(servletGroup);
                roleMapping2.put(servletGroup, casGroup);                
            } else if(key.startsWith("attribute.")) {
                String sessionAttribute = key.replaceFirst("^attribute\\.", "");
                String casAttribute = e.getValue().toString();
                attributeMapping.put(casAttribute, sessionAttribute);
            }
        }
        logger.trace("mapping is role={} attributes={}", roleMapping2, attributeMapping);
    }

    @Override
    public String[] getRoles(Principal principal) {
        String[] casRoles = super.getRoles(principal);
        List<String> roleList = new ArrayList<>(casRoles.length);
        for(String role: casRoles) {
            if(roleMapping1.containsKey(role)) {
                roleList.addAll(roleMapping1.get(role));
            }
        }
        logger.trace("roles for {} are {}", principal, roleList);
        return (String[]) roleList.toArray();
    }

    @Override
    public boolean hasRole(Principal principal, String role) {    
        logger.trace("search if {} as role {}", principal, role);
        if(roleMapping2.containsKey(role)) {
            role = roleMapping2.get(role);
        }
        return super.hasRole(principal, role);            
    }

    @Override
    public SecurityConstraint[] findSecurityConstraints(final Request arg0,
            final Context arg1) {
        if(!overrideSecurity || headerFilterMatches(arg0)) {
            return super.findSecurityConstraints(arg0, arg1);
        }
        //Default case, install security
        synchronized(security) {
            if(security.scs == null) {
                security.configure(arg1);
            }       
        }
        return security.scs;            
    }

    @Override
    public boolean hasResourcePermission(Request arg0, Response arg1,
            SecurityConstraint[] arg2, Context arg3) throws IOException {
        boolean hasResourcePermission;
        if( ! overrideSecurity || headerFilterMatches(arg0)) {
            hasResourcePermission = super.hasResourcePermission(arg0, arg1, arg2, arg3);
        } else {
            hasResourcePermission = true;
        }
        // if hasResourcePermission, try to fill session attributes
        if(hasResourcePermission) {
            Principal p = arg0.getPrincipal();
            HttpSession sess = arg0.getSession();
            if(sess != null) {
                synchronized(sess) {
                    // Only resolve mapping if Principal is a CAS generated principal
                    // It also uses the __CAS__ as a flag that mapping has already been done
                    // So it's not needed again.
                    // org.jasig.cas.client.validation.Assertion can't be used, it's still empty
                    if(p != null && p instanceof AttributePrincipal && sess.getAttribute("__CAS_ATTRIBUTES_DONE__") == null) {
                        AttributePrincipal ap = (AttributePrincipal) p;
                        logger.debug("mapping attribute found: {}", ap.getAttributes());
                        for(Entry<String, Object> e: ap.getAttributes().entrySet()) {
                            String attribute = e.getKey();
                            // Only explicitely mapped attribute are kept
                            if(attributeMapping.containsKey(attribute)) {
                                attribute = attributeMapping.get(attribute);
                                sess.setAttribute(attribute, e.getValue());
                            }
                        }
                        sess.setAttribute("__CAS_ATTRIBUTES_DONE__", Boolean.TRUE);
                    }            
                }            
            }            
        }
        return hasResourcePermission;
    }

    @Override
    public boolean hasUserDataPermission(Request arg0, Response arg1,
            SecurityConstraint[] arg2) throws IOException {
        if( overrideSecurity || headerFilterMatches(arg0)) {
            return super.hasUserDataPermission(arg0, arg1, arg2);
        }
        return true;
    }

    /**
     * Check if the filter header match the given regex pattern
     * @param req
     * @return
     */
    private boolean headerFilterMatches(Request req) {
        if(filter != null && headerFilter != null) {
            String headerValue = req.getHeader(headerFilter);
            if(headerValue != null) {
                return filter.matcher(headerValue).matches();
            }
        }
        return false;
    }

    public void setOverrideSecurity(boolean overrideSecurity) {
        this.overrideSecurity = overrideSecurity;
    }

    public String getFilter() {
        if(filter == null) {
            return null;
        }
        return filter.pattern();
    }

    public void setFilter(String filter) {
        this.filter = Pattern.compile(filter);
    }

    public String getHeaderFilter() {
        return headerFilter;
    }

    public void setHeaderFilter(String headerFilter) {
        this.headerFilter = headerFilter;
    }

}
