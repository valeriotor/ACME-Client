package com.valeriotor.acme;

import javax.json.JsonObject;
import javax.json.JsonValue;

public class Identifier {

    private final String type;
    private final String value;

    public Identifier(String type, String value) {
        this.type = type;
        this.value = value;
    }

    public Identifier(String value) {
        this.type = "dns";
        this.value = value;
    }

    public Identifier(JsonValue json) {
        this(json.asJsonObject());
    }

    public Identifier(JsonObject json) {
        this.type = json.getString("type");
        this.value = json.getString("value");
    }

    public String getType() {
        return type;
    }

    public String getValue() {
        return value;
    }

    @Override
    public String toString() {
        return "{" +
                "\"type\":\"" + type + '\"' +
                ", \"value\":\"" + value + '\"' +
                '}';
    }
}
