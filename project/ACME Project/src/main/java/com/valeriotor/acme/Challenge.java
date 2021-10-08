package com.valeriotor.acme;

import javax.json.*;
import java.io.StringReader;
import java.net.http.HttpResponse;
import java.util.List;

public class Challenge {
    private final ChallengeType type;
    private final String token;
    private final String url;
    private final String status;

    public static List<Challenge> getChallengesFromAuthorizationResponse(HttpResponse<String> authorizationJson) {
        JsonReader reader = Json.createReader(new StringReader(authorizationJson.body()));
        JsonObject object = reader.readObject();
        JsonArray challenges = object.getJsonArray("challenges");
        return challenges.getValuesAs(Challenge::new);
    }

    public Challenge(JsonValue jsonValue) {
        this(jsonValue.asJsonObject());
    }

    public Challenge(JsonObject jsonObject) {
        this(ChallengeType.fromString(jsonObject.getString("type")),
                jsonObject.getString("token", null),
                jsonObject.getString("url"),
                jsonObject.getString("status"));
    }

    public Challenge(ChallengeType type, String token, String url, String status) {
        this.type = type;
        this.token = token;
        this.url = url;
        this.status = status;
    }

    public ChallengeType getType() {
        return type;
    }

    public String getToken() {
        return token;
    }

    public String getUrl() {
        return url;
    }

    public String getStatus() {
        return status;
    }
}
