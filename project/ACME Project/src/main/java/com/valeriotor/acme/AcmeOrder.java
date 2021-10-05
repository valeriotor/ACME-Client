package com.valeriotor.acme;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.JsonValue;
import java.io.StringReader;
import java.util.List;
import java.util.stream.Collectors;

public class AcmeOrder {
    private final String status;
    private final String expires;
    private final String notBefore;
    private final String notAfter;
    private final List<String> authorizations;
    private final String finalize;
    private final String certificate;
    private final List<Identifier> identifiers;
    private final JsonObject error;


    public AcmeOrder(String jsonOrder) {
        JsonReader reader = Json.createReader(new StringReader(jsonOrder));
        JsonObject jsonObject = reader.readObject();
        this.status = jsonObject.getString("status");
        this.expires = jsonObject.getString("expires", null);
        this.notBefore = jsonObject.getString("notBefore", null);
        this.notAfter = jsonObject.getString("notAfter", null);
        this.authorizations = jsonObject.getJsonArray("authorizations")
                .getValuesAs(JsonValue::toString)
                .stream()
                .map(s -> s.replaceAll("\"", ""))
                .collect(Collectors.toList());
        this.finalize = jsonObject.getString("finalize");
        this.certificate = jsonObject.getString("certificate", null);
        this.identifiers = jsonObject.getJsonArray("identifiers").getValuesAs(Identifier::new);
        this.error = jsonObject.getJsonObject("error");
    }

    public String getStatus() {
        return status;
    }

    public String getExpires() {
        return expires;
    }

    public String getNotBefore() {
        return notBefore;
    }

    public String getNotAfter() {
        return notAfter;
    }

    public List<String> getAuthorizations() {
        return authorizations;
    }

    public String getFinalize() {
        return finalize;
    }

    public String getCertificate() {
        return certificate;
    }

    public List<Identifier> getIdentifiers() {
        return identifiers;
    }

    public JsonObject getError() {
        return error;
    }

    @Override
    public String toString() {
        return "AcmeOrder{" +
                "status='" + status + '\'' +
                ", expires='" + expires + '\'' +
                ", notBefore='" + notBefore + '\'' +
                ", notAfter='" + notAfter + '\'' +
                ", authorizations=" + authorizations +
                ", finalize='" + finalize + '\'' +
                ", certificate='" + certificate + '\'' +
                ", identifiers=" + identifiers +
                ", error=" + error +
                '}';
    }
}
