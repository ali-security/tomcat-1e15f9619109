/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.apache.catalina.authenticator;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import jakarta.security.auth.message.AuthException;
import jakarta.security.auth.message.AuthStatus;
import jakarta.security.auth.message.MessageInfo;
import jakarta.security.auth.message.MessagePolicy;
import jakarta.security.auth.message.callback.PasswordValidationCallback;
import jakarta.security.auth.message.config.AuthConfigFactory;
import jakarta.security.auth.message.config.AuthConfigProvider;
import jakarta.security.auth.message.config.ServerAuthConfig;
import jakarta.security.auth.message.module.ServerAuthModule;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import org.apache.catalina.Context;
import org.apache.catalina.authenticator.jaspic.SimpleAuthConfigProvider;
import org.apache.catalina.realm.GenericPrincipal;
import org.apache.catalina.startup.TesterMapRealm;
import org.apache.catalina.startup.TesterServlet;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.startup.TomcatBaseTest;
import org.apache.tomcat.util.buf.ByteChunk;
import org.apache.tomcat.util.descriptor.web.LoginConfig;

/**
 * Tests for the JASPIC handling in {@link AuthenticatorBase}.
 */
public class TestAuthenticatorBaseJaspic extends TomcatBaseTest {

    private static final String MODULE_KEY = "org.apache.catalina.authenticator.jaspic.ServerAuthModule.1";

    private static final String USER_HEADER = "X-Test-User";
    private static final String PASSWORD_HEADER = "X-Test-Password";

    // The CallbackHandler class each ServerAuthModule was initialised with
    private static final List<String> INITIALISED_HANDLERS = new CopyOnWriteArrayList<>();
    // The CallbackHandler class of each ServerAuthModule that cleaned a Subject
    private static final List<String> CLEANED_SUBJECT_HANDLERS = new CopyOnWriteArrayList<>();

    private final List<String> registrationIDs = new ArrayList<>();


    @Before
    public void clearRecords() {
        INITIALISED_HANDLERS.clear();
        CLEANED_SUBJECT_HANDLERS.clear();
    }


    @After
    public void removeRegistrations() {
        for (String registrationID : registrationIDs) {
            AuthConfigFactory.getFactory().removeRegistration(registrationID);
        }
        registrationIDs.clear();
    }


    /*
     * CVE-2026-75973. When several web applications share the default SimpleAuthConfigProvider, each one must
     * authenticate against its own Realm rather than the Realm of the first web application to authenticate a
     * request.
     */
    @Test
    public void testDefaultProviderUsesRealmOfEachContext() throws Exception {
        registerDefaultProvider(TesterServerAuthModulePassword.class);

        Tomcat tomcat = getTomcatInstance();
        addContextWithRealm(tomcat, "/a", "userA", "passwordA");
        addContextWithRealm(tomcat, "/b", "userB", "passwordB");

        tomcat.start();

        // The first request initialises JASPIC for /a
        Assert.assertEquals(HttpServletResponse.SC_OK, doRequest("/a", "userA", "passwordA"));
        // /b must use its own Realm: a user of /a is not a user of /b
        Assert.assertEquals(HttpServletResponse.SC_FORBIDDEN, doRequest("/b", "userA", "passwordA"));
        Assert.assertEquals(HttpServletResponse.SC_OK, doRequest("/b", "userB", "passwordB"));
        Assert.assertEquals(HttpServletResponse.SC_FORBIDDEN, doRequest("/a", "userB", "passwordB"));
    }


    /*
     * CVE-2026-75973. When several web applications share the default SimpleAuthConfigProvider, each one must use its
     * own ServerAuthConfig (and therefore its own CallbackHandler) rather than the one created for the first web
     * application to authenticate a request.
     */
    @Test
    public void testDefaultProviderUsesCallbackHandlerOfEachContext() throws Exception {
        registerDefaultProvider(TesterServerAuthModulePassword.class);

        Tomcat tomcat = getTomcatInstance();
        addContext(tomcat, "/a", TesterCallbackHandlerA.class, new TesterServlet());
        addContext(tomcat, "/b", TesterCallbackHandlerB.class, new TesterServlet());

        tomcat.start();

        // The first request initialises JASPIC for /a
        Assert.assertEquals(HttpServletResponse.SC_OK, doRequest("/a", "userA", "passwordA"));
        // /b must use its own CallbackHandler: a user of /a is not a user of /b
        Assert.assertEquals(HttpServletResponse.SC_FORBIDDEN, doRequest("/b", "userA", "passwordA"));
        Assert.assertEquals(HttpServletResponse.SC_OK, doRequest("/b", "userB", "passwordB"));
        Assert.assertEquals(HttpServletResponse.SC_FORBIDDEN, doRequest("/a", "userB", "passwordB"));
    }


    /*
     * The ServerAuthConfig, and with it the ServerAuthModule instances, is created once per web application and then
     * re-used, for requests that are authenticated by the Authenticator and for calls to
     * HttpServletRequest.authenticate().
     */
    @Test
    public void testServerAuthConfigCreatedOncePerContext() throws Exception {
        registerDefaultProvider(TesterServerAuthModulePassword.class);

        Tomcat tomcat = getTomcatInstance();
        addContext(tomcat, "/a", TesterCallbackHandlerA.class, new TesterAuthenticateServlet());
        addContext(tomcat, "/b", TesterCallbackHandlerB.class, new TesterAuthenticateServlet());

        tomcat.start();

        for (int i = 0; i < 3; i++) {
            Assert.assertEquals(HttpServletResponse.SC_OK, doRequest("/a", "userA", "passwordA"));
            Assert.assertEquals(HttpServletResponse.SC_OK, doRequest("/b", "userB", "passwordB"));
        }

        Assert.assertEquals(2, INITIALISED_HANDLERS.size());
        Assert.assertTrue(INITIALISED_HANDLERS.contains(TesterCallbackHandlerA.class.getName()));
        Assert.assertTrue(INITIALISED_HANDLERS.contains(TesterCallbackHandlerB.class.getName()));
    }


    /*
     * HttpServletRequest.logout() must clean the Subject with the ServerAuthConfig of the web application.
     */
    @Test
    public void testLogoutUsesServerAuthConfigOfContext() throws Exception {
        registerDefaultProvider(TesterServerAuthModulePassword.class);

        Tomcat tomcat = getTomcatInstance();
        addContext(tomcat, "/a", TesterCallbackHandlerA.class, new TesterServlet());
        addContext(tomcat, "/b", TesterCallbackHandlerB.class, new TesterLogoutServlet());

        tomcat.start();

        Assert.assertEquals(HttpServletResponse.SC_OK, doRequest("/a", "userA", "passwordA"));
        Assert.assertEquals(HttpServletResponse.SC_OK, doRequest("/b", "userB", "passwordB"));

        Assert.assertEquals(Collections.singletonList(TesterCallbackHandlerB.class.getName()),
                CLEANED_SUBJECT_HANDLERS);
    }


    /*
     * A change of the provider registration must be picked up by the Authenticator even though it caches the
     * ServerAuthConfig.
     */
    @Test
    public void testProviderRegistrationChange() throws Exception {
        registerDefaultProvider(TesterServerAuthModulePassword.class);

        Tomcat tomcat = getTomcatInstance();
        addContext(tomcat, "/a", TesterCallbackHandlerA.class, new TesterServlet());

        tomcat.start();

        Assert.assertEquals(HttpServletResponse.SC_OK, doRequest("/a", "userA", "passwordA"));

        // Replace the default registration
        registerDefaultProvider(TesterServerAuthModuleDeny.class);

        Assert.assertEquals(HttpServletResponse.SC_FORBIDDEN, doRequest("/a", "userA", "passwordA"));
    }


    /*
     * If the provider cannot create a ServerAuthConfig the request fails with a 500 response and the ServerAuthConfig
     * is created again for the next request.
     */
    @Test
    public void testServerAuthConfigFailureIsRetried() throws Exception {
        Map<String,Object> properties = new HashMap<>();
        properties.put(MODULE_KEY, TesterServerAuthModulePassword.class.getName());
        registerDefaultProvider(new TesterFailOnceAuthConfigProvider(properties));

        Tomcat tomcat = getTomcatInstance();
        addContext(tomcat, "/a", TesterCallbackHandlerA.class, new TesterServlet());

        tomcat.start();

        ByteChunk bc = new ByteChunk();
        int rc = getUrl("http://localhost:" + getPort() + "/a/", bc, createHeaders("userA", "passwordA"), null);
        Assert.assertEquals(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, rc);
        Assert.assertFalse(bc.toString(), bc.toString().contains("Exception"));

        Assert.assertEquals(HttpServletResponse.SC_OK, doRequest("/a", "userA", "passwordA"));
    }


    private void addContextWithRealm(Tomcat tomcat, String contextPath, String user, String password) {
        Context ctx = tomcat.addContext(contextPath, null);
        Tomcat.addServlet(ctx, "servlet", new TesterServlet());
        ctx.addServletMappingDecoded("/", "servlet");
        // Web application specific Realm used by the default CallbackHandler
        TesterMapRealm realm = new TesterMapRealm();
        realm.addUser(user, password);
        ctx.setRealm(realm);
    }


    private void addContext(Tomcat tomcat, String contextPath, Class<? extends CallbackHandler> callbackHandlerClass,
            HttpServlet servlet) {
        Context ctx = tomcat.addContext(contextPath, null);
        Tomcat.addServlet(ctx, "servlet", servlet);
        ctx.addServletMappingDecoded("/", "servlet");
        // Use an Authenticator with a web application specific CallbackHandler
        ctx.setLoginConfig(new LoginConfig("NONE", null, null, null));
        NonLoginAuthenticator authenticator = new NonLoginAuthenticator();
        authenticator.setJaspicCallbackHandlerClass(callbackHandlerClass.getName());
        ctx.getPipeline().addValve(authenticator);
    }


    private int doRequest(String contextPath, String user, String password) throws IOException {
        ByteChunk bc = new ByteChunk();
        int rc = getUrl("http://localhost:" + getPort() + contextPath + "/", bc, createHeaders(user, password), null);
        if (rc == HttpServletResponse.SC_OK) {
            Assert.assertEquals("OK", bc.toString());
        }
        return rc;
    }


    private static Map<String,List<String>> createHeaders(String user, String password) {
        Map<String,List<String>> reqHeaders = new HashMap<>();
        reqHeaders.put(USER_HEADER, Collections.singletonList(user));
        reqHeaders.put(PASSWORD_HEADER, Collections.singletonList(password));
        return reqHeaders;
    }


    private void registerDefaultProvider(Class<? extends ServerAuthModule> moduleClass) {
        Map<String,Object> properties = new HashMap<>();
        properties.put(MODULE_KEY, moduleClass.getName());
        registerDefaultProvider(new SimpleAuthConfigProvider(properties, null));
    }


    private void registerDefaultProvider(AuthConfigProvider provider) {
        String registrationID = AuthConfigFactory.getFactory().registerConfigProvider(provider, null, null, "Test");
        if (!registrationIDs.contains(registrationID)) {
            registrationIDs.add(registrationID);
        }
    }


    /*
     * Validates the user name and password from the request headers with a PasswordValidationCallback, i.e. with the
     * CallbackHandler the module was initialised with.
     */
    public static class TesterServerAuthModulePassword implements ServerAuthModule {

        private CallbackHandler handler;

        @Override
        public void initialize(MessagePolicy requestPolicy, MessagePolicy responsePolicy, CallbackHandler handler,
                Map<String,Object> options) throws AuthException {
            this.handler = handler;
            INITIALISED_HANDLERS.add(handler.getClass().getName());
        }

        @Override
        public Class<?>[] getSupportedMessageTypes() {
            return new Class<?>[] { HttpServletRequest.class, HttpServletResponse.class };
        }

        @Override
        public AuthStatus validateRequest(MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject)
                throws AuthException {
            HttpServletRequest request = (HttpServletRequest) messageInfo.getRequestMessage();
            HttpServletResponse response = (HttpServletResponse) messageInfo.getResponseMessage();

            String user = request.getHeader(USER_HEADER);
            String password = request.getHeader(PASSWORD_HEADER);
            if (user != null && password != null) {
                PasswordValidationCallback pvc =
                        new PasswordValidationCallback(clientSubject, user, password.toCharArray());
                try {
                    handler.handle(new Callback[] { pvc });
                } catch (IOException | UnsupportedCallbackException e) {
                    throw new AuthException(e);
                }
                if (pvc.getResult()) {
                    return AuthStatus.SUCCESS;
                }
            }

            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            return AuthStatus.SEND_FAILURE;
        }

        @Override
        public AuthStatus secureResponse(MessageInfo messageInfo, Subject serviceSubject) throws AuthException {
            return AuthStatus.SEND_SUCCESS;
        }

        @Override
        public void cleanSubject(MessageInfo messageInfo, Subject subject) throws AuthException {
            CLEANED_SUBJECT_HANDLERS.add(handler.getClass().getName());
        }
    }


    /*
     * Rejects every request.
     */
    public static class TesterServerAuthModuleDeny extends TesterServerAuthModulePassword {

        @Override
        public AuthStatus validateRequest(MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject)
                throws AuthException {
            ((HttpServletResponse) messageInfo.getResponseMessage()).setStatus(HttpServletResponse.SC_FORBIDDEN);
            return AuthStatus.SEND_FAILURE;
        }
    }


    /*
     * A web application specific user store: accepts a single user.
     */
    public abstract static class TesterCallbackHandlerBase implements CallbackHandler {

        private final String validUser;
        private final String validPassword;

        protected TesterCallbackHandlerBase(String validUser, String validPassword) {
            this.validUser = validUser;
            this.validPassword = validPassword;
        }

        @Override
        public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            for (Callback callback : callbacks) {
                if (callback instanceof PasswordValidationCallback pvc) {
                    boolean valid = validUser.equals(pvc.getUsername()) &&
                            validPassword.equals(String.valueOf(pvc.getPassword()));
                    pvc.setResult(valid);
                    if (valid) {
                        pvc.getSubject().getPrivateCredentials()
                                .add(new GenericPrincipal(pvc.getUsername(), Collections.emptyList()));
                    }
                } else {
                    throw new UnsupportedCallbackException(callback);
                }
            }
        }
    }


    public static class TesterCallbackHandlerA extends TesterCallbackHandlerBase {
        public TesterCallbackHandlerA() {
            super("userA", "passwordA");
        }
    }


    public static class TesterCallbackHandlerB extends TesterCallbackHandlerBase {
        public TesterCallbackHandlerB() {
            super("userB", "passwordB");
        }
    }


    /*
     * Fails to create a ServerAuthConfig on the first call.
     */
    public static class TesterFailOnceAuthConfigProvider extends SimpleAuthConfigProvider {

        private final AtomicBoolean failed = new AtomicBoolean(false);

        public TesterFailOnceAuthConfigProvider(Map<String,Object> properties) {
            super(properties, null);
        }

        @Override
        public ServerAuthConfig getServerAuthConfig(String layer, String appContext, CallbackHandler handler)
                throws AuthException {
            if (failed.compareAndSet(false, true)) {
                throw new AuthException();
            }
            return super.getServerAuthConfig(layer, appContext, handler);
        }
    }


    /*
     * Authenticates the request (again) with HttpServletRequest.authenticate().
     */
    public static class TesterAuthenticateServlet extends HttpServlet {

        private static final long serialVersionUID = 1L;

        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
            if (req.authenticate(resp)) {
                resp.setContentType("text/plain");
                resp.getWriter().print("OK");
            }
        }
    }


    /*
     * Logs the authenticated user out with HttpServletRequest.logout().
     */
    public static class TesterLogoutServlet extends HttpServlet {

        private static final long serialVersionUID = 1L;

        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
            req.logout();
            resp.setContentType("text/plain");
            resp.getWriter().print("OK");
        }
    }
}
