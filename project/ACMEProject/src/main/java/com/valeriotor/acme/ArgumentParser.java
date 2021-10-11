package com.valeriotor.acme;

import java.util.ArrayList;
import java.util.List;

public class ArgumentParser {


    private static ArgumentParser instance;

    private final ChallengeType challenge;
    private List<String> domains = new ArrayList<>();
    private String directoryUrl;
    private String dnsRecord;
    private boolean revoke = false;

    public static void tryCreateInstance(String[] args) {
        if (instance == null) {
            instance = new ArgumentParser(args);
        }
    }

    public static ArgumentParser getInstance() {
        return instance;
    }


    public ArgumentParser(String[] args) {
        challenge = args[0].equals("dns01") ? ChallengeType.DNS : ChallengeType.HTTPS;
        Option currentOption = null;
        for (int i = 1; i < args.length; i++) {
            String arg = args[i];
            if (currentOption == null) {
                for (Option o : Option.values()) {
                    if (o.name.equalsIgnoreCase(arg)) {
                        if (o != Option.REVOKE) {
                            currentOption = o;
                        } else {
                            revoke = true;
                        }
                        break;
                    }
                }
            } else {
                switch (currentOption) {
                    case DOMAIN:
                        domains.add(arg);
                        break;
                    case DIRECTORY:
                        directoryUrl = arg;
                        break;
                    case RECORD:
                        dnsRecord = arg;
                        break;
                }
                currentOption = null;
            }
        }
    }

    public ChallengeType getChallenge() {
        return challenge;
    }

    public List<String> getDomains() {
        return domains;
    }

    public String getDirectoryUrl() {
        return directoryUrl;
    }

    public String getDnsRecord() {
        return dnsRecord;
    }

    public boolean isRevoke() {
        return revoke;
    }

    @Override
    public String toString() {
        return "ArgumentParser{" +
                "challenge=" + challenge +
                ", domains=" + domains +
                ", directoryUrl='" + directoryUrl + '\'' +
                ", dnsRecord='" + dnsRecord + '\'' +
                ", revoke=" + revoke +
                '}';
    }

    private enum Option {
        DOMAIN("--domain"), DIRECTORY("--dir"), RECORD("--record"), REVOKE("--revoke");

        private final String name;

        Option(String name) {
            this.name = name;
        }
    }

}
