package org.jasig.cas.client.tomcat.v7;

import java.beans.BeanInfo;
import java.beans.IntrospectionException;
import java.beans.Introspector;
import java.beans.PropertyDescriptor;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URL;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.naming.InvalidNameException;
import javax.servlet.http.HttpSession;

import org.apache.catalina.Context;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.deploy.SecurityConstraint;
import org.jasig.cas.client.authentication.AttributePrincipal;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

public class TestMappedAssertionCasRealm {

    @Test
    public void doNoSecurity() {
        MappedAssertionCasRealm realm = new MappedAssertionCasRealm();

        realm.setOverrideSecurity(false);

        Request r = new Request();
        r = Mockito.spy(r);
        Context c = Mockito.mock(Context.class);

        SecurityConstraint[] scs = realm.findSecurityConstraints(r, c);

        Assert.assertNull(scs);
    }

    @Test
    public void doWithSecurity() {
        MappedAssertionCasRealm realm = new MappedAssertionCasRealm();

        realm.setOverrideSecurity(true);

        Request r = Mockito.mock(Request.class);
        Context c = Mockito.mock(Context.class);

        SecurityConstraint[] scs = realm.findSecurityConstraints(r, c);
        String[] pattern = scs[0].findCollections()[0].findPatterns();
        Assert.assertEquals(1, scs.length);
        Assert.assertArrayEquals(new String[]{"/*"}, pattern);
        Assert.assertTrue(scs[0].getAllRoles());
    }

    @Test
    public void doBypassSecurity() {
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
    public void testSessionFill1() throws IOException, InvalidNameException {
        checkSession(true);
    }

    @Test
    public void testSessionFill2() throws IOException, InvalidNameException {
        checkSession(false);
    }

    private void checkSession(boolean override) throws FileNotFoundException, InvalidNameException, IOException {

        URL mappingprop = getClass().getClassLoader().getResource("mapping.properties");

        MappedAssertionCasRealm realm = new MappedAssertionCasRealm();
        realm.setOverrideSecurity(override);
        realm.setMappingProperties(mappingprop.getFile());

        Context c = Mockito.mock(Context.class);
        Mockito.when(c.findSecurityRoles()).thenReturn(new String[] {});

        final Map<String, Object> sessionAttributes = new HashMap<>();
        HttpSession sess = Mockito.mock(HttpSession.class);
        Mockito.doAnswer(new Answer<Object>() {
            public Object answer(InvocationOnMock invocation) {
                Object[] args = invocation.getArguments();
                String key = (String) args[0];
                Object value =  args[1];
                sessionAttributes.put(key, value);
                return null;
            }           
        }).when(sess).setAttribute(Mockito.anyString(), Mockito.anyObject());
        Mockito.doAnswer(new Answer<Object>() {
            public Object answer(InvocationOnMock invocation) {
                return Collections.enumeration(sessionAttributes.values());
            }           
        }).when(sess).getAttributeNames();

        AttributePrincipal ap = Mockito.mock(AttributePrincipal.class);
        Map<String, Object> attributes = Collections.singletonMap("displayName", (Object)"Joe Happy");
        Mockito.when(ap.getAttributes()).thenReturn(attributes);

        Request req = Mockito.mock(Request.class);
        Mockito.when(req.getPrincipal()).thenReturn(ap);
        Mockito.when(req.getContext()).thenReturn(c);
        Mockito.when(req.getSession()).thenReturn(sess);

        Response rep = Mockito.mock(Response.class);

        boolean hasResourcePermission = realm.hasResourcePermission(req, rep, realm.findSecurityConstraints(req, c), c);

        Assert.assertTrue(hasResourcePermission);
        Assert.assertEquals(Boolean.TRUE, sessionAttributes.get("__CAS_ATTRIBUTES_DONE__"));
        Assert.assertEquals("Joe Happy", sessionAttributes.get("name"));

    }

    @Test
    public void checkBeans() throws IntrospectionException {

        Set<String> beans = new HashSet<String>(Arrays.asList("roleAttributeName", "overrideSecurity", "headerFilter", "filter", "allRolesMode", "mappingProperties"));

        BeanInfo info = Introspector.getBeanInfo(MappedAssertionCasRealm.class);
        PropertyDescriptor[] pds = info.getPropertyDescriptors();
        for(PropertyDescriptor i: pds) {
            if(i.getWriteMethod() != null) {
                beans.remove(i.getName());
            }
        }

        Assert.assertEquals("missing beans:" + beans, 0, beans.size());

    }

}
