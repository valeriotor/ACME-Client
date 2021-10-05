package com.valeriotor.acme.util;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class HTTPUtil {

    public static HttpResponse<String> postRequest(String url, String message) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                .header("Content-Type", "application/jose+json")
                .POST(HttpRequest.BodyPublishers.ofString(message))
                .build();

        HttpResponse<String> response = HttpClient.newHttpClient()
                .send(request, HttpResponse.BodyHandlers.ofString());
        NonceUtil.getInstance().updateNonce(response);
        return response;
    }

}
