package com.valeriotor.acme;

import java.io.IOException;
import java.net.http.HttpResponse;

public class AccountManager {

    private static AccountManager instance;
    private final String accountUrl;

    public static void tryCreateInstance(HttpResponse<String> newAccountResponse) throws IOException, InterruptedException {
        if (instance == null) {
            instance = new AccountManager(newAccountResponse.headers().firstValue("Location").get());
        }
    }

    public static AccountManager getInstance() {
        return instance;
    }

    private AccountManager(String accountUrl) {
        this.accountUrl = accountUrl;
    }

    public String getAccountUrl() {
        return accountUrl;
    }
}
