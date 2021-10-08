package com.valeriotor.acme.util;

import com.valeriotor.acme.AccountManager;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

public class JWSUtil {

    private static final String jwkTemplate = "{\"alg\":\"RS256\",\n" +
            "      \"e\":\"%s\",\n" +
            "      \"kty\":\"RSA\",\n" +
            "      \"n\":\"%s\"\n" +
            "     }";

    private static final String tinyJwkTemplate = "{\"e\":\"%s\",\"kty\":\"RSA\",\"n\":\"%s\"}";

    private static int kid = 1;
    private static JWSUtil instance;

    private final PrivateKey privateKey;
    private final RSAPublicKey publicKey;

    public static void tryCreateInstance() throws NoSuchAlgorithmException {
        if (instance == null) {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.generateKeyPair();
            RSAPublicKey publicKey = (RSAPublicKey) kp.getPublic();
            PrivateKey privateKey = kp.getPrivate();
            instance = new JWSUtil(privateKey, publicKey);
        }
    }

    public static JWSUtil getInstance() {
        return instance;
    }

    public JWSUtil(PrivateKey privateKey, RSAPublicKey publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    public String flattenedSignedJson(String headerJson, String payloadJson) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        String headerString = new String(Base64.getUrlEncoder().withoutPadding().encode(headerJson.replaceAll("\\s+", "").getBytes(StandardCharsets.UTF_8)));
        String payloadString = new String(Base64.getUrlEncoder().withoutPadding().encode(payloadJson.replaceAll("\\s+", "").getBytes(StandardCharsets.UTF_8)));
        String messageString = headerString + "." + payloadString;

        Signature signing = Signature.getInstance("SHA256withRSA");
        signing.initSign(privateKey);
        signing.update(messageString.getBytes(StandardCharsets.UTF_8), 0, messageString.length());
        byte[] signature = signing.sign();
        String signatureString = new String(Base64.getUrlEncoder().withoutPadding().encode(signature));
        return String.format("{\"payload\":\"%s\",\"protected\":\"%s\",\"signature\":\"%s\"}", payloadString, headerString, signatureString);
    }

    public String generateProtectedHeaderJwk(String url) throws IOException, InterruptedException {
        String nonce = NonceUtil.getInstance().getNonce();
        String jwk = generateJwk();
        return  "{\n" +
                "       \"alg\": \"RS256\",\n" +
                "       \"jwk\": " + jwk + ",\n" +
                "       \"nonce\": \"" + nonce + "\",\n" +
                "       \"url\": \"" + url + "\"\n" +
                "     }";
    }

    public String generateProtectedHeaderKid(String url) throws IOException, InterruptedException {
        String nonce = NonceUtil.getInstance().getNonce();
        String kid = AccountManager.getInstance().getAccountUrl();
        return  "{\n" +
                "       \"alg\": \"RS256\",\n" +
                "       \"kid\":\"" + kid + "\",\n" +
                "       \"nonce\": \"" + nonce + "\",\n" +
                "       \"url\": \"" + url + "\"\n" +
                "     }";
    }

    private String generateJwk() {
        return String.format(jwkTemplate,
                new String(Base64.getUrlEncoder().withoutPadding().encode(publicKey.getPublicExponent().toByteArray())),
                new String(Base64.getUrlEncoder().withoutPadding().encode(publicKey.getModulus().toByteArray())));
    }

    private String generateTinyJwk() {
        byte[] bytes = publicKey.getModulus().toByteArray();
        if (bytes.length > 256) {
            byte[] temp = new byte[256];
            for (int i = bytes.length-256; i < bytes.length; i++) {
                temp[i + 256 - bytes.length] = bytes[i];
            }
            bytes = temp;
        }
        return String.format(tinyJwkTemplate,
                new String(Base64.getUrlEncoder().withoutPadding().encode(publicKey.getPublicExponent().toByteArray())),
                new String(Base64.getUrlEncoder().withoutPadding().encode(bytes)));
    }

    private String generateBase64JwkThumbprint() throws NoSuchAlgorithmException {
        String jwk = generateTinyJwk().replaceAll("\\s+", "");
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(jwk.getBytes(StandardCharsets.UTF_8));
        return new String(Base64.getUrlEncoder().withoutPadding().encode(hash));
    }

    public String generateKeyAuthorization(String token) throws NoSuchAlgorithmException {
        return token + "." + generateBase64JwkThumbprint();
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public RSAPublicKey getPublicKey() {
        return publicKey;
    }
}
