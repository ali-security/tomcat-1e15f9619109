/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.apache.coyote.http2;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import jakarta.servlet.AsyncContext;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.Assert;
import org.junit.Test;

import org.apache.catalina.Context;
import org.apache.catalina.Wrapper;
import org.apache.catalina.startup.Tomcat;

/*
 * Section 5.7 of the Servlet specification - Closure of the Response Object.
 *
 * A non-blocking write of exactly content-length bytes must be allowed to complete in a non-blocking manner. Closing
 * the response as part of that write must not trigger a blocking flush that holds the container thread until the
 * client increases the flow control window (or the stream write timeout expires and the response is truncated).
 */
public class TestAsyncContentLength extends Http2TestBase {

    private static final int BODY_SIZE = ConnectionSettingsBase.DEFAULT_INITIAL_WINDOW_SIZE * 2;

    @Test
    public void testNonBlockingWriteExactContentLength() throws Exception {
        CountDownLatch writeReturned = new CountDownLatch(1);

        enableHttp2();

        Tomcat tomcat = getTomcatInstance();

        Context ctxt = getProgrammaticRootContext();
        Tomcat.addServlet(ctxt, "simple", new SimpleServlet());
        ctxt.addServletMappingDecoded("/simple", "simple");
        Wrapper w = Tomcat.addServlet(ctxt, "async", new ContentLengthAsyncServlet(writeReturned));
        w.setAsyncSupported(true);
        ctxt.addServletMappingDecoded("/async", "async");
        tomcat.start();

        openClientConnection();
        doHttpUpgrade();
        sendClientPreface();
        validateHttp2InitialResponse();

        // Reset connection window size after initial response
        sendWindowUpdate(0, SimpleServlet.CONTENT_LENGTH);

        // Send request
        byte[] frameHeader = new byte[9];
        ByteBuffer headersPayload = ByteBuffer.allocate(128);
        buildGetRequest(frameHeader, headersPayload, null, 3, "/async");
        writeFrame(frameHeader, headersPayload);

        // Headers
        parser.readFrame();
        // Body - only as much as the initial flow control window allows
        while (output.getBytesRead() < ConnectionSettingsBase.DEFAULT_INITIAL_WINDOW_SIZE) {
            parser.readFrame();
        }
        Assert.assertEquals(ConnectionSettingsBase.DEFAULT_INITIAL_WINDOW_SIZE, output.getBytesRead());

        // The non-blocking write must return without waiting for the client to increase the flow control window
        Assert.assertTrue("Non-blocking write of content-length bytes did not complete in a non-blocking manner",
                writeReturned.await(5, TimeUnit.SECONDS));

        // Allow the remainder of the response body to be sent
        sendWindowUpdate(0, BODY_SIZE);
        sendWindowUpdate(3, BODY_SIZE);

        while (!output.getTrace().endsWith("3-EndOfStream\n")) {
            parser.readFrame();
        }

        // Check that the complete response body was received
        Assert.assertEquals(BODY_SIZE, output.getBytesRead());
    }


    public static class ContentLengthAsyncServlet extends HttpServlet {

        private static final long serialVersionUID = 1L;

        private final transient CountDownLatch writeReturned;

        public ContentLengthAsyncServlet(CountDownLatch writeReturned) {
            this.writeReturned = writeReturned;
        }

        @Override
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {

            final AsyncContext asyncContext = request.startAsync();

            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType("application/binary");
            response.setContentLength(BODY_SIZE);

            final ServletOutputStream output = response.getOutputStream();
            output.setWriteListener(new WriteListener() {

                private volatile boolean written = false;

                @Override
                public void onWritePossible() throws IOException {
                    if (!written) {
                        written = true;
                        // Write exactly content-length bytes in a single non-blocking write
                        output.write(new byte[BODY_SIZE]);
                        writeReturned.countDown();
                    }
                    if (output.isReady()) {
                        asyncContext.complete();
                    }
                }

                @Override
                public void onError(Throwable t) {
                    t.printStackTrace();
                }
            });
        }
    }
}
