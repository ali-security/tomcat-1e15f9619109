/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.catalina.realm;

import java.net.InetAddress;
import java.security.Principal;
import java.util.Arrays;
import java.util.Collection;
import java.util.Hashtable;
import java.util.List;

import javax.naming.Context;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;

import org.apache.catalina.realm.JNDIRealm.JNDIConnection;
import org.apache.juli.logging.LogFactory;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.listener.InMemoryRequestHandler;
import com.unboundid.ldap.listener.InMemorySASLBindHandler;
import com.unboundid.ldap.sdk.AddRequest;
import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;

/**
 * Tests that, when the JNDIRealm validates credentials by binding as the user (i.e. no userPassword attribute is
 * configured), a simple bind using the user provided name and password is always used regardless of the
 * authentication mechanism configured for the realm's own connection to the directory.
 */
@RunWith(Parameterized.class)
public class TestJNDIRealmBindAsUser {

    private static final String USER_PATTERN = "cn={0},ou=people,dc=example,dc=com";
    private static final String USERNAME = "test";
    private static final String PASSWORD = "test";

    private static InMemoryDirectoryServer ldapServer;

    @Parameterized.Parameters(name = "{index}: authentication[{0}]")
    public static Collection<Object[]> parameters() {
        return Arrays.asList(new Object[][] {
                { null },
                { "none" },
                { "simple" },
                { "EXTERNAL" } });
    }

    @Parameter(0)
    public String authentication;

    private JNDIRealm realm;


    @Before
    public void createRealm() {
        realm = new JNDIRealm();
        realm.containerLog = LogFactory.getLog(TestJNDIRealmBindAsUser.class);

        realm.setConnectionURL("ldap://localhost:" + ldapServer.getListenPort());
        realm.setAuthentication(authentication);
        // No userPassword so credentials are validated by binding as the user
        realm.setUserPattern(USER_PATTERN);
    }


    @After
    public void closeRealm() throws Exception {
        if (realm != null) {
            // close() releases the lock obtained by get()
            realm.close(realm.get());
        }
    }


    @Test
    public void testValidPassword() {
        Principal p = realm.authenticate(USERNAME, PASSWORD);
        Assert.assertNotNull(p);
        Assert.assertEquals(USERNAME, p.getName());
    }


    @Test
    public void testInvalidPassword() {
        Assert.assertNull(realm.authenticate(USERNAME, "wrong-password"));
    }


    @Test
    public void testEmptyPassword() {
        Assert.assertNull(realm.authenticate(USERNAME, ""));
    }


    @Test
    public void testUnknownUser() {
        Assert.assertNull(realm.authenticate("unknown", "any-password"));
    }


    @Test
    public void testInvalidThenValidPassword() throws Exception {
        Assert.assertNull(realm.authenticate(USERNAME, "wrong-password"));
        assertConfiguredAuthenticationRestored();

        Principal p = realm.authenticate(USERNAME, PASSWORD);
        Assert.assertNotNull(p);
        Assert.assertEquals(USERNAME, p.getName());
        assertConfiguredAuthenticationRestored();

        Assert.assertNull(realm.authenticate(USERNAME, "wrong-password"));
        assertConfiguredAuthenticationRestored();
    }


    private void assertConfiguredAuthenticationRestored() throws Exception {
        JNDIConnection connection = realm.get();
        try {
            Hashtable<?,?> env = connection.context.getEnvironment();
            Assert.assertEquals(authentication, env.get(Context.SECURITY_AUTHENTICATION));
            Assert.assertNull(env.get(Context.SECURITY_PRINCIPAL));
            Assert.assertNull(env.get(Context.SECURITY_CREDENTIALS));
        } finally {
            realm.release(connection);
        }
    }


    @BeforeClass
    public static void createLDAP() throws Exception {
        InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig("dc=example,dc=com");
        InetAddress localhost = InetAddress.getByName("localhost");
        InMemoryListenerConfig listenerConfig =
                new InMemoryListenerConfig("localListener", localhost, 0, null, null, null);
        config.setListenerConfigs(listenerConfig);
        // Simulate a directory server that accepts SASL EXTERNAL (e.g. based on a TLS client certificate) for the
        // connection used by the realm
        config.addSASLBindHandler(new ExternalSASLBindHandler());
        ldapServer = new InMemoryDirectoryServer(config);

        ldapServer.startListening();

        try (LDAPConnection conn = ldapServer.getConnection()) {
            AddRequest addBase = new AddRequest(
                    "dn: dc=example,dc=com",
                    "objectClass: top",
                    "objectClass: domain",
                    "dc: example");
            LDAPResult result = conn.processOperation(addBase);
            Assert.assertEquals(ResultCode.SUCCESS, result.getResultCode());

            AddRequest addPeople = new AddRequest(
                    "dn: ou=people,dc=example,dc=com",
                    "objectClass: top",
                    "objectClass: organizationalUnit");
            result = conn.processOperation(addPeople);
            Assert.assertEquals(ResultCode.SUCCESS, result.getResultCode());

            AddRequest addUserTest = new AddRequest(
                    "dn: cn=test,ou=people,dc=example,dc=com",
                    "objectClass: top",
                    "objectClass: person",
                    "objectClass: organizationalPerson",
                    "cn: test",
                    "sn: Test",
                    "userPassword: " + PASSWORD);
            result = conn.processOperation(addUserTest);
            Assert.assertEquals(ResultCode.SUCCESS, result.getResultCode());
        }
    }


    @AfterClass
    public static void destroyLDAP() {
        ldapServer.shutDown(true);
    }


    private static class ExternalSASLBindHandler extends InMemorySASLBindHandler {

        @Override
        public String getSASLMechanismName() {
            return "EXTERNAL";
        }

        @Override
        public BindResult processSASLBind(InMemoryRequestHandler handler, int messageID, DN bindDN,
                ASN1OctetString credentials, List<Control> controls) {
            return new BindResult(messageID, ResultCode.SUCCESS, null, null, null, null);
        }
    }
}
