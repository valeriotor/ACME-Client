package com.valeriotor.acme.http;

import fi.iki.elonen.NanoHTTPD;

import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;

public class HTTPCertificateServer extends NanoHTTPD {
    public HTTPCertificateServer(int port) {
        super(port);
    }

    @Override
    public void start() throws IOException {
        super.start();
        System.out.println("Certificate server started");
    }

    @Override
    protected ClientHandler createClientHandler(Socket finalAccept, InputStream inputStream) {
        System.out.println("Creating client handler");
        return super.createClientHandler(finalAccept, inputStream);
    }

    @Override
    public Response serve(IHTTPSession session) {
        System.out.println("Received HTTPS request");
        return newFixedLengthResponse("Test");
    }

}
