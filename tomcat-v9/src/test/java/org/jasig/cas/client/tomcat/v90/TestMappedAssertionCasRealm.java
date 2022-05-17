package org.jasig.cas.client.tomcat.v90;

import java.beans.BeanInfo;
import java.beans.IntrospectionException;
import java.beans.Introspector;
import java.beans.PropertyDescriptor;
import java.io.IOException;
import java.net.URL;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import javax.servlet.http.HttpSession;

import org.apache.catalina.Context;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.tomcat.util.descriptor.web.SecurityConstraint;
import org.jasig.cas.client.authentication.AttributePrincipal;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockito.Mockito;
import org.mockito.stubbing.Answer;

public class TestMappedAssertionCasRealm {

    @BeforeClass
    public static void setLogger() {
        System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "trace");
    }

    @Test
    public void doBypassSecurityUA() {
        MappedAssertionCasRealm realm = new MappedAssertionCasRealm();

        realm.setOverrideSecurity(true);
        realm.setFilter("curl.*");
        realm.setHeaderFilter("User-Agent");

        Request r = Mockito.mock(Request.class);
        Mockito.when(r.getHeader("User-Agent")).thenReturn("curl 1.0");
        Context c = Mockito.mock(Context.class);

        SecurityConstraint[] scs = realm.findSecurityConstraints(r, c);
        Assert.assertNull(scs);
    }

    @Test
    public void doNotBypassSecurityUA() {
        MappedAssertionCasRealm realm = new MappedAssertionCasRealm();

        realm.setOverrideSecurity(true);
        realm.setFilter("curl.*");
        realm.setHeaderFilter("User-Agent");
        Request r = Mockito.mock(Request.class);
        Mockito.when(r.getHeader("User-Agent")).thenReturn("Mozilla");
        Mockito.when(r.getRequestURI()).thenReturn("/");
        Mockito.when(r.getMethod()).thenReturn("GET");
        Context c = Mockito.mock(Context.class);

        SecurityConstraint[] scs = realm.findSecurityConstraints(r, c);
        Assert.assertNotNull(scs);
    }

    @Test
    public void doNotBypassSecurityURI() {
        MappedAssertionCasRealm realm = new MappedAssertionCasRealm();
        realm.setOverrideSecurity(true);
        realm.setAccesslist("-/skip;+/test");

        Request r = Mockito.mock(Request.class);
        Mockito.when(r.getRequestURI()).thenReturn("/test");
        Mockito.when(r.getMethod()).thenReturn("GET");
        Context c = Mockito.mock(Context.class);

        SecurityConstraint[] scs = realm.findSecurityConstraints(r, c);
        Assert.assertNotNull(scs);
    }

    @Test
    public void doBypassSecurityURI() {
        MappedAssertionCasRealm realm = new MappedAssertionCasRealm();
        realm.setOverrideSecurity(true);
        realm.setAccesslist("-/skip;+/test");

        Request r = Mockito.mock(Request.class);
        Mockito.when(r.getRequestURI()).thenReturn("/skip");
        Mockito.when(r.getMethod()).thenReturn("GET");
        Context c = Mockito.mock(Context.class);

        SecurityConstraint[] scs = realm.findSecurityConstraints(r, c);
        Assert.assertNull(scs);
    }

    @Test
    public void testSessionFill1() throws IOException {
        Map<String, Object> sessionAttributes = checkSession(true);
        Assert.assertEquals(Boolean.TRUE, sessionAttributes.get("__CAS_ATTRIBUTES_DONE__"));
        Assert.assertEquals("Joe Happy", sessionAttributes.get("name"));
    }

    @Test
    public void testSessionFill2() throws IOException {
        Map<String, Object> sessionAttributes = checkSession(false);
        Assert.assertFalse(sessionAttributes.containsKey("__CAS_ATTRIBUTES_DONE__"));
        Assert.assertFalse(sessionAttributes.containsKey("name"));
    }

    private Map<String, Object> checkSession(boolean override) throws IOException {
        URL mappingprop = getClass().getClassLoader().getResource("mapping.properties");

        MappedAssertionCasRealm realm = new MappedAssertionCasRealm();
        realm.setOverrideSecurity(override);
        realm.setMappingProperties(mappingprop.getFile());

        Context c = Mockito.mock(Context.class);
        Mockito.when(c.findSecurityRoles()).thenReturn(new String[] {});

        Map<String, Object> sessionAttributes = new HashMap<>();
        HttpSession sess = Mockito.mock(HttpSession.class);
        Mockito.doAnswer((Answer<Object>) invocation -> {
            Object[] args = invocation.getArguments();
            String key = (String) args[0];
            Object value = args[1];
            sessionAttributes.put(key, value);
            return null;
        }).when(sess).setAttribute(Mockito.anyString(), Mockito.any());
        Mockito.doAnswer((Answer<Object>) invocation -> Collections.enumeration(sessionAttributes.values())).when(sess).getAttributeNames();

        AttributePrincipal ap = Mockito.mock(AttributePrincipal.class);
        Map<String, Object> attributes = Collections.singletonMap("displayName", "Joe Happy");
        Mockito.when(ap.getAttributes()).thenReturn(attributes);

        Request req = Mockito.mock(Request.class);
        Mockito.when(req.getPrincipal()).thenReturn(ap);
        Mockito.when(req.getContext()).thenReturn(c);
        Mockito.when(req.getSession()).thenReturn(sess);
        Mockito.when(req.getMethod()).thenReturn("GET");
        Mockito.when(req.getRequestURI()).thenReturn("/");

        Response rep = Mockito.mock(Response.class);

        boolean hasResourcePermission = realm.hasResourcePermission(req, rep, realm.findSecurityConstraints(req, c), c);

        Assert.assertTrue(hasResourcePermission);
        return sessionAttributes;
    }

    @Test
    public void checkBeans() throws IntrospectionException {
        Set<String> beans = Arrays.stream(new String[]{"roleAttributeName", "overrideSecurity", "headerFilter", "filter", "allRolesMode", "mappingProperties", "accesslist"}).collect(
                Collectors.toSet());

        BeanInfo info = Introspector.getBeanInfo(MappedAssertionCasRealm.class);
        PropertyDescriptor[] pds = info.getPropertyDescriptors();
        for (PropertyDescriptor i: pds) {
            if (i.getWriteMethod() != null) {
                beans.remove(i.getName());
            }
        }

        Assert.assertEquals("missing beans:" + beans, 0, beans.size());
    }

}
