package com.valeriotor.acme;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;
import java.io.IOException;
import java.io.StringReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class AcmeDirContainer {
    private static AcmeDirContainer instance;
    private final String newAccountUrl;
    private final String newNonceUrl;
    private final String newOrderUrl;
    private final String revokeCertificateUrl;
    private final String keyChangeUrl;
    private final JsonObject meta;

    public static void tryCreateInstance() throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(URI.create(ArgumentParser.getInstance().getDirectoryUrl()))
                .GET()
                .build();

        HttpResponse<String> send = HttpClient.newHttpClient()
                .send(request, HttpResponse.BodyHandlers.ofString());
        String json = send.body();
        instance = new AcmeDirContainer(json);
    }

    public static AcmeDirContainer getInstance() {
        return instance;
    }

    private AcmeDirContainer(String jsonDir) {
        JsonReader reader = Json.createReader(new StringReader(jsonDir));
        JsonObject jsonObject = reader.readObject();
        newAccountUrl = jsonObject.getString("newAccount");
        newNonceUrl = jsonObject.getString("newNonce");
        newOrderUrl = jsonObject.getString("newOrder");
        revokeCertificateUrl = jsonObject.getString("revokeCert");
        keyChangeUrl = jsonObject.getString("keyChange");
        meta = jsonObject.getJsonObject("meta");
    }

    public String getNewAccountUrl() {
        return newAccountUrl;
    }

    public String getNewNonceUrl() {
        return newNonceUrl;
    }

    public String getNewOrderUrl() {
        return newOrderUrl;
    }

    public String getRevokeCertificateUrl() {
        return revokeCertificateUrl;
    }

    public String getKeyChangeUrl() {
        return keyChangeUrl;
    }

    public JsonObject getMeta() {
        return meta;
    }

    @Override
    public String toString() {
        return "AcmeDirContainer{" +
                "newAccountUrl='" + newAccountUrl + '\'' +
                ", newNonceUrl='" + newNonceUrl + '\'' +
                ", newOrderUrl='" + newOrderUrl + '\'' +
                ", revokeCertificateUrl='" + revokeCertificateUrl + '\'' +
                ", keyChangeUrl='" + keyChangeUrl + '\'' +
                ", meta=" + meta +
                '}';
    }
}
