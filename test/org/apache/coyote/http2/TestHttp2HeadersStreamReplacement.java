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

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.Assert;
import org.junit.Test;

import org.apache.catalina.Context;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;
import org.apache.coyote.Request;
import org.apache.coyote.http11.AbstractHttp11Protocol;
import org.apache.tomcat.util.http.MimeHeaders;

/**
 * Tests that headers received for a stream after that stream has been replaced (and the associated request and
 * response recycled) by the container thread are not passed to the replaced stream.
 */
public class TestHttp2HeadersStreamReplacement extends Http2TestBase {

    private static final String TRAILER_MARKER_NAME = "x-trailer-marker";
    private static final String INJECTED_VALUE = "injected";


    @Test
    public void testTrailerHeadersAfterStreamReplacement() throws Exception {
        http2Connect();

        TrackingHttp2Protocol trackingProtocol = (TrackingHttp2Protocol) http2Protocol;

        ((AbstractHttp11Protocol<?>) http2Protocol.getHttp11Protocol()).setAllowedTrailerHeaders(TRAILER_HEADER_NAME);

        // POST request on stream 3 with no end of stream so trailer headers can follow
        byte[] headersFrameHeader = new byte[9];
        ByteBuffer headersPayload = ByteBuffer.allocate(128);
        byte[] dataFrameHeader = new byte[9];
        ByteBuffer dataPayload = ByteBuffer.allocate(128);
        buildPostRequest(headersFrameHeader, headersPayload, false, dataFrameHeader, dataPayload, null, true, 3);
        writeFrame(headersFrameHeader, headersPayload);

        // Start the trailer field block but do not complete it (no end of headers flag)
        byte[] trailerFrameHeader = new byte[9];
        ByteBuffer trailerPayload = ByteBuffer.allocate(128);
        MimeHeaders trailerStart = new MimeHeaders();
        trailerStart.addValue(TRAILER_MARKER_NAME).setString("start");
        hpackEncoder.encode(trailerStart, trailerPayload);
        trailerPayload.flip();
        ByteUtil.setThreeBytes(trailerFrameHeader, 0, trailerPayload.limit());
        trailerFrameHeader[3] = FrameType.HEADERS.getIdByte();
        // Flags. end of stream (0x01)
        trailerFrameHeader[4] = 0x01;
        ByteUtil.set31Bits(trailerFrameHeader, 5, 3);
        writeFrame(trailerFrameHeader, trailerPayload);

        /*
         * Processing of the trailer marker releases the servlet processing stream 3. The servlet returns without
         * reading the request body so the container thread resets the stream, replaces it and recycles the associated
         * request and response. Wait for that to complete before the rest of the trailer field block is sent.
         */
        Assert.assertTrue(trackingProtocol.requestRecycled.await(10, TimeUnit.SECONDS));

        // Complete the trailer field block
        byte[] continuationFrameHeader = new byte[9];
        ByteBuffer continuationPayload = ByteBuffer.allocate(128);
        MimeHeaders trailerEnd = new MimeHeaders();
        trailerEnd.addValue(TRAILER_HEADER_NAME).setString(INJECTED_VALUE);
        hpackEncoder.encode(trailerEnd, continuationPayload);
        continuationPayload.flip();
        ByteUtil.setThreeBytes(continuationFrameHeader, 0, continuationPayload.limit());
        continuationFrameHeader[3] = FrameType.CONTINUATION.getIdByte();
        // Flags. end of headers (0x04)
        continuationFrameHeader[4] = 0x04;
        ByteUtil.set31Bits(continuationFrameHeader, 5, 3);
        writeFrame(continuationFrameHeader, continuationPayload);

        // New request on stream 5 that will re-use the recycled request and response
        output.setTraceBody(true);
        byte[] frameHeader = new byte[9];
        ByteBuffer getPayload = ByteBuffer.allocate(128);
        buildGetRequest(frameHeader, getPayload, null, 5, "/trailers");
        writeFrame(frameHeader, getPayload);

        int frames = 0;
        while (!output.getTrace().contains("5-EndOfStream") && frames < 20) {
            parser.readFrame();
            frames++;
        }

        String trace = output.getTrace();
        Assert.assertTrue(trace, trace.contains("5-EndOfStream"));
        // The trailer field received for the replaced stream must not leak into the request for stream 5
        Assert.assertFalse(trace, trace.contains(INJECTED_VALUE));
        Assert.assertTrue(trace, trace.contains("5-Body-trailers={}\n"));
    }


    @Override
    protected void enableHttp2(long maxConcurrentStreams, boolean tls, long readTimeout, long writeTimeout,
            long keepAliveTimeout, long streamReadTimout, long streamWriteTimeout) {
        Tomcat tomcat = getTomcatInstance();
        Connector connector = tomcat.getConnector();
        Assert.assertTrue(connector.setProperty("useAsyncIO", Boolean.toString(useAsyncIO)));
        http2Protocol = new TrackingHttp2Protocol();
        http2Protocol.setReadTimeout(readTimeout);
        http2Protocol.setWriteTimeout(writeTimeout);
        http2Protocol.setKeepAliveTimeout(keepAliveTimeout);
        http2Protocol.setStreamReadTimeout(streamReadTimout);
        http2Protocol.setStreamWriteTimeout(streamWriteTimeout);
        http2Protocol.setMaxConcurrentStreams(maxConcurrentStreams);
        http2Protocol.setHttp11Protocol((AbstractHttp11Protocol<?>) connector.getProtocolHandler());
        connector.addUpgradeProtocol(http2Protocol);
    }


    @Override
    protected void configureAndStartWebApplication() throws LifecycleException {
        Tomcat tomcat = getTomcatInstance();

        // Retain '/simple' url-pattern since it enables code re-use
        Context ctxt = getProgrammaticRootContext();
        Tomcat.addServlet(ctxt, "blocking", new BlockingPostServlet((TrackingHttp2Protocol) http2Protocol));
        ctxt.addServletMappingDecoded("/simple", "blocking");
        Tomcat.addServlet(ctxt, "trailers", new TrailerFieldsServlet());
        ctxt.addServletMappingDecoded("/trailers", "trailers");

        tomcat.start();
    }


    private static class TrackingHttp2Protocol extends Http2Protocol {

        private final CountDownLatch trailerBlockStarted = new CountDownLatch(1);
        private final CountDownLatch requestRecycled = new CountDownLatch(1);

        @Override
        public String getHttpUpgradeName(boolean isSSLEnabled) {
            return "h2c";
        }

        @Override
        boolean isTrailerHeaderAllowed(String headerName) {
            if (TRAILER_MARKER_NAME.equals(headerName)) {
                trailerBlockStarted.countDown();
            }
            return super.isTrailerHeaderAllowed(headerName);
        }

        @Override
        void pushRequestAndResponse(Request requestAndResponse) {
            super.pushRequestAndResponse(requestAndResponse);
            if (trailerBlockStarted.getCount() == 0) {
                requestRecycled.countDown();
            }
        }
    }


    private static class BlockingPostServlet extends SimpleServlet {

        private static final long serialVersionUID = 1L;

        private final transient TrackingHttp2Protocol protocol;

        BlockingPostServlet(TrackingHttp2Protocol protocol) {
            this.protocol = protocol;
        }

        @Override
        protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
            // Wait until the trailer field block has started then return without reading the request body
            try {
                protocol.trailerBlockStarted.await(10, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                throw new ServletException(e);
            }
            resp.setStatus(HttpServletResponse.SC_OK);
        }
    }


    private static class TrailerFieldsServlet extends HttpServlet {

        private static final long serialVersionUID = 1L;

        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
            resp.setContentType("text/plain");
            resp.setCharacterEncoding("UTF-8");
            resp.getWriter().print("trailers=" + req.getTrailerFields());
        }
    }
}
