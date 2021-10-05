package com.valeriotor.acme.http;

import fi.iki.elonen.NanoHTTPD;

public class HTTPShutdownServer extends NanoHTTPD {
    private final Runnable shutdownMethod;

    public HTTPShutdownServer(int port, Runnable shutdownMethod) {
        super(port);
        this.shutdownMethod = shutdownMethod;
    }

    @Override
    public Response serve(IHTTPSession session) {
        if ("/shutdown".equalsIgnoreCase(session.getUri())) {
            Thread shutdown = new Thread(shutdownMethod);
            shutdown.start();
        }
        return newFixedLengthResponse("helloo");
    }
}
