package com.valeriotor.acme.http;

import fi.iki.elonen.NanoHTTPD;

public class HTTPCertificateServer extends NanoHTTPD {
    private final String certificate;
    public HTTPCertificateServer(int port, String certificate) {
        super(port);
        this.certificate = certificate;
    }

    @Override
    public Response serve(IHTTPSession session) {
        System.out.println("boi");
        return newFixedLengthResponse("response");
    }
}
