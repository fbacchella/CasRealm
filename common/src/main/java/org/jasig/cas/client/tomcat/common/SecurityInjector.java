package org.jasig.cas.client.tomcat.common;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BiFunction;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.jasig.cas.client.authentication.AttributePrincipal;
import org.slf4j.Logger;

public class SecurityInjector<SC, CT, RQ extends HttpServletRequest, RS extends HttpServletResponse> {

    private static final Pattern splitter = Pattern.compile("\\s*(?<!\\\\);\\s*");
    private static final Pattern extractor = Pattern.compile("^(role|attribute)\\.(.*)$");

    static class UrlFilter<SC> {
        private final boolean restricted;
        private final String pattern;
        private final SC constraint;
        UrlFilter(char mode, String pattern, BiFunction <Boolean, String, SC> provider) {
            if (mode == '+') {
                restricted = true;
            } else if (mode == '-') {
                restricted = false;
            } else {
                throw new IllegalArgumentException("Illegal mode " + mode + " for URL pattern " + pattern);
            }
            this.pattern = pattern;
            constraint = provider.apply(restricted, pattern);
        }

        public SC getConstraint() {
            return constraint;
        }

        @Override
        public String toString() {
            return (restricted ? "+" : "-") + pattern;
        }
    }

    private SC[] security = null;
    private final AtomicBoolean ctxRoles = new AtomicBoolean(false);

    // Map CAS group to one or many servlet role
    private final Map<String, Set<String>> roleMapping1 = new HashMap<>();
    // Map a servlet role to a CAS group
    private final Map<String, Set<String>> roleMapping2 = new HashMap<>();

    //Map a CAS attribute to a session attribute
    private final Map<String, String> attributeMapping = new HashMap<>();

    private final List<UrlFilter<SC>> urlFilterList = new ArrayList<>();

    //Filter for direct access
    private Pattern filter = null;
    private String headerFilter = null;

    private boolean overrideSecurity = true;

    private final Logger logger;
    private final RealmProvider<SC, CT, RQ, RS> casrealm;

    public SecurityInjector(Logger logger, RealmProvider<SC, CT, RQ, RS> casrealm) {
        this.logger = logger;
        this.casrealm = casrealm;
        setAccesslist("+/*");
    }

    public void setMappingProperties(String propFile) {
        Properties prop = new Properties();
        try (FileReader fr = new FileReader(propFile)){
            prop.load(fr);
        } catch (FileNotFoundException e) {
            throw new IllegalArgumentException("file " + propFile + " not found ", e);
        } catch (IOException e) {
            throw new IllegalArgumentException("file " + propFile + " can't be read ", e);
        }
        for (Map.Entry<Object, Object> e: prop.entrySet()) {
            String key = e.getKey().toString();
            String attribute = "";
            Matcher extracted = extractor.matcher(e.getKey().toString());
            if (extracted.matches()) {
                key = extracted.group(1);
                attribute = extracted.group(2);
            }
            switch (key) {
            case "role": {
                roleMapping2.put(attribute, new HashSet<>());
                for (String casGroup : splitter.split(e.getValue().toString())) {
                    roleMapping1.computeIfAbsent(casGroup, k -> new HashSet<>()).add(attribute);
                    roleMapping2.get(attribute).add(casGroup);
                }
                break;
            }
            case "attribute": {
                String casAttribute = e.getValue().toString();
                attributeMapping.put(casAttribute, attribute);
                break;
            }
            case "accesslist":
                this.setAccesslist(e.getValue().toString());
                break;
            default:
                logger.warn("Unknown property {}", key);
            }
        }
    }

    public String[] getRoles(Principal principal) {
        String[] casRoles = casrealm.getRoles(principal);
        Set<String> roleList = new HashSet<>(casRoles.length);
        for (String role: casRoles) {
            if (roleMapping1.containsKey(role)) {
                roleList.addAll(roleMapping1.get(role));
            }
        }
        logger.debug("roles for {} are {}", principal, roleList);
        return roleList.stream().toArray(String[]::new);
    }

    public boolean hasRole(Principal principal, String role) {
        if (roleMapping2.containsKey(role)) {
            for (String roleMapped: roleMapping2.get(role)) {
                if (casrealm.superHasRole(principal, roleMapped)) {
                    return true;
                }
            }
        }
        return false;
    }

    public SC[] findSecurityConstraints(RQ request, CT ctx) {
        //Default case, install security
        synchronized(ctxRoles) {
            if (! ctxRoles.get()) {
                roleMapping2.keySet().forEach(i -> casrealm.addSecurityRole(i, ctx));
                ctxRoles.set(true);
            }
        }
        return checkAccess(request, () -> security, () -> casrealm.superFindSecurityConstraints(request, ctx));
    }

    private <T> T checkAccess(RQ request, Supplier<T> intercept, Supplier<T> bypass) {
        if (!overrideSecurity || headerFilterMatches(request)) {
            return bypass.get();
        } else if (overrideSecurity) {
            for (UrlFilter<SC> i: urlFilterList) {
                if (i.restricted && casrealm.isIncluded(i.constraint, request.getRequestURI(), request.getMethod())) {
                    return intercept.get();
                }
            }
            return bypass.get();
        } else {
            return bypass.get();
        }
    }

    // Construct a new SecurityCollection, that will
    // override the one given in the web.xml
    private SC[] configureSecurityConstraint() {
        return urlFilterList
                .stream()
                .map(UrlFilter::getConstraint)
                .toArray(casrealm::newSecurityContext);
    }

    private void fillSession(Principal p, HttpSession sess) {
        if (sess != null) {
            synchronized(sess) {
                if (logger.isDebugEnabled()) {
                    logger.debug("looking for cas attributes in session {}, with attributes {}", sess.getId(), Collections.list(sess.getAttributeNames()));
                }
                // Only resolve mapping if Principal is a CAS generated principal
                // It also uses the __CAS__ as a flag that mapping has already been done
                // So it's not needed again.
                // org.jasig.cas.client.validation.Assertion can't be used, it's still empty
                if (p instanceof AttributePrincipal && sess.getAttribute("__CAS_ATTRIBUTES_DONE__") == null) {
                    AttributePrincipal ap = (AttributePrincipal) p;
                    for (Map.Entry<String, Object> e: ap.getAttributes().entrySet()) {
                        String attribute = e.getKey();
                        // Only explicitely mapped attribute are kept
                        if (attributeMapping.containsKey(attribute)) {
                            attribute = attributeMapping.get(attribute);
                            sess.setAttribute(attribute, e.getValue());
                        }
                    }
                    sess.setAttribute("__CAS_ATTRIBUTES_DONE__", true);
                }
            }
        }
    }

    /**
     * Check if the filter header match the given regex pattern
     * @param req the request
     * @return true if it matches the header filtering
     */
    public boolean headerFilterMatches(RQ req) {
        if (filter != null && headerFilter != null) {
            String headerValue = req.getHeader(headerFilter);
            if (headerValue != null) {
                return filter.matcher(headerValue).matches();
            }
        }
        return false;
    }

    public void setOverrideSecurity(boolean overrideSecurity) {
        this.overrideSecurity = overrideSecurity;
    }

    public String getFilter() {
        return Optional.ofNullable(filter).map(Pattern::pattern).orElse(null);
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

    public void setAccesslist(String accesslist) {
        urlFilterList.clear();
        for (String description: splitter.split(accesslist)) {
            try {
                char mode = description.charAt(0);
                String pattern = description.substring(1);
                urlFilterList.add(new UrlFilter<>(mode, pattern, casrealm::buildConstraint));
            } catch (IllegalArgumentException ex) {
                logger.warn("Illegal access list {}: {}", description, ex.getMessage());
            }
        }
        security = configureSecurityConstraint();
    }

    public boolean hasUserDataPermission(RQ request, RS response,
            SC[] constraints, Principal principal) throws IOException {
        Supplier<Boolean> checksuper = () -> {
            try {
                return casrealm.superHasUserDataPermission(request, response, constraints);
            } catch (IOException ex) {
                throw new UncheckedIOException(ex);
            }
        };
        Supplier<Boolean> checksuperwithfill = () -> {
            fillSession(principal, request.getSession());
            return checksuper.get();
        };
        try {
            return checkAccess(request, checksuperwithfill , checksuper);
        } catch (UncheckedIOException e) {
            throw e.getCause();
        }
    }

    public boolean hasResourcePermission(RQ request,
            RS response, SC[] constraints,
            CT context, Principal principal) throws  IOException{
        Supplier<Boolean> checksuper = () -> {
            try {
                return casrealm.superHasResourcePermission(request, response, constraints, context);
            } catch (IOException ex) {
                throw new UncheckedIOException(ex);
            }
        };
        Supplier<Boolean> checksuperwithfill = () -> {
            fillSession(principal, request.getSession());
            return checksuper.get();
        };
        try {
            return checkAccess(request, checksuperwithfill , checksuper);
        } catch (UncheckedIOException e) {
            throw e.getCause();
        }
    }

}
