package com.valeriotor.acme.http;

import fi.iki.elonen.NanoHTTPD;

import java.util.concurrent.atomic.AtomicReference;

public class HTTPChallengeServer extends NanoHTTPD {

    private AtomicReference<String> keyAuthorization = new AtomicReference<>();

    public HTTPChallengeServer(int port) {
        super(port);
    }

    public void setKeyAuthorization(String keyAuthorization) {
        this.keyAuthorization.set(keyAuthorization);
    }

    @Override
    public Response serve(IHTTPSession session) {
        Response r = newFixedLengthResponse(keyAuthorization.get());
        r.addHeader("Content-Type", "application/octet-stream");
        System.out.println(keyAuthorization.get());
        return r;
    }
}
