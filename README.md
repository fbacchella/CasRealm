About the project
-----------------

Some applications don't expect to be protected by CAS, or manage there security themselves (like gitblit).
Usual security realms expect the application to be already secured.

This realm replace the application security with it's own, so every thing is protected. It can also use 
one of the CAS attribute find roles.
It also also uses session to store CAS attribute that can be read by the application.

Both roles and attributes can be mapped to good values, that will be used by the application.

It extends `org.jasig.cas.client.tomcat.v6.PropertiesCasRealm`, but there is only a version for Tomcat 7
as it needs servlet api 3.0, so no Tomcat 6 and PropertiesCasRealm don't support Tomcat 8.

Configuration
-------------

a example configuration is

    <?xml version="1.0" encoding="UTF-8"?>
    <Context privileged="true" antiResourceLocking="false"
             docBase="${catalina.home}/webapps/manager">
      <!--
        The following configuration uses the SAML 1.1 protocol and role data
        provided by the assertion to enable dynamic server-driven role data.
        The attribute used for role data is "memberOf".
      -->
      <Realm
        className="org.jasig.cas.client.tomcat.v7.MappedAssertionCasRealm" 
        roleAttributeName="memberOf"
        rolesMappingProperties="${catalina.home}/conf/casRoles.properties"
        />
      <Valve
        className="org.jasig.cas.client.tomcat.v7.Cas20CasAuthenticator"
        encoding="UTF-8"
        casServerLoginUrl="https://casserver/login"
        casServerUrlPrefix="https://casserver/cas"
        serverName="localhost"
        />
    </Context>

The `roleAttributeName` gives the CAS attribute where the role names are to be found.

The `rolesMappingProperties` gives the path to a file with an enumeration of roles and attributes mapping.

The file format is a list of either

    role.<rolename>=CAS group
    attribute.<application attribute>=CAS attribute

Only mapped attributes and roles are set, to avoid unespected name collisions.

The `overrideSecurity` boolean setting can be set to `false` to only use mapping services of this realm, if
the application is already CAS friendly.

With the options `filter` and `headerFilter`, it's possible to bypass the `overrideSecurity`. If the given
header matches the regex given in `filter`, the permission is delegated to the default configuration. This
must be used with care, because it can totally bypass security and should be only used when the application
or other setting already enforce security. It allows dummy clients that can't' authenticate using CAS to keep
using the application.

Installation
------------
It's a usual maven project so it's build with a `mvn package` command. It generate a `target/cas-client-tomcat-mandatoryrealm-v7-1.0-SNAPSHOT-jar-with-dependencies.jar`
that must be installed in the lib folder installion (not in your webapp). Also don't install `cas-client-tomcat-mandatoryrealm-v7-1.0-SNAPSHOT.jar`,
as it don't include the dependencies.
