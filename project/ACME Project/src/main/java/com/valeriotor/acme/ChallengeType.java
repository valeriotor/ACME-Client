package com.valeriotor.acme;

public enum ChallengeType {
    DNS, HTTPS;

    public static ChallengeType fromString(String s) {
        if ("dns01".equals(s) || "dns-01".equals(s)) {
            return DNS;
        } else if ("http01".equals(s) || "http-01".equals(s)) {
            return HTTPS;
        } else {
            return null;
        }
    }
}
