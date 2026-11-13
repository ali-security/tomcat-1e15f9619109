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
package org.apache.catalina.authenticator.jaspic;

import java.util.HashMap;
import java.util.Map;

import jakarta.security.auth.message.config.ServerAuthConfig;

import org.junit.Assert;
import org.junit.Test;

public class TestSimpleAuthConfigProvider {

    private static final String SERVER_AUTH_MODULE_KEY_PREFIX =
            "org.apache.catalina.authenticator.jaspic.ServerAuthModule.";

    /*
     * CVE-2026-75973. The provider may be shared by several web applications so it must not return the
     * ServerAuthConfig created for one web application to another.
     */
    @Test
    public void testServerAuthConfigNotSharedBetweenContexts() throws Exception {
        Map<String,Object> properties = new HashMap<>();
        properties.put(SERVER_AUTH_MODULE_KEY_PREFIX + "1", TesterServerAuthModuleA.class.getName());

        SimpleAuthConfigProvider provider = new SimpleAuthConfigProvider(properties, null);

        ServerAuthConfig configA = provider.getServerAuthConfig("HttpServlet", "localhost /a", null);
        ServerAuthConfig configB = provider.getServerAuthConfig("HttpServlet", "localhost /b", null);

        Assert.assertEquals("localhost /a", configA.getAppContext());
        Assert.assertEquals("localhost /b", configB.getAppContext());
        Assert.assertNotSame(configA, configB);
    }
}
