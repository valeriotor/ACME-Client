package com.valeriotor.acme.util;

import com.valeriotor.acme.AcmeDirContainer;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class NonceUtil {

    private static NonceUtil instance;

    private final String acmeNonceUrl;
    private String nextNonce;

    public static void tryCreateInstance() {
        if (instance == null) {
            AcmeDirContainer container = AcmeDirContainer.getInstance();
            instance = new NonceUtil(container.getNewNonceUrl());
        }
    }

    public static NonceUtil getInstance() {
        return instance;
    }

    private NonceUtil(String acmeNonceUrl) {
        this.acmeNonceUrl = acmeNonceUrl;
    }

    public String getNonce() throws IOException, InterruptedException {
        if (nextNonce != null) {
            return nextNonce;
        } else {
            HttpRequest request = HttpRequest.newBuilder(URI.create(acmeNonceUrl))
                    .GET() //no HEAD method?
                    .build();

            HttpResponse<String> response = HttpClient.newHttpClient()
                    .send(request, HttpResponse.BodyHandlers.ofString());

            nextNonce = response.headers().firstValue("Replay-Nonce").get();
            return nextNonce;
        }
    }

    public void updateNonce(HttpResponse<String> response) {
        nextNonce = response.headers().firstValue("Replay-Nonce").get();
    }

}
