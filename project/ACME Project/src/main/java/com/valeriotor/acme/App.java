package com.valeriotor.acme;

import com.valeriotor.acme.http.HTTPChallengeServer;
import com.valeriotor.acme.http.HTTPShutdownServer;
import com.valeriotor.acme.util.HTTPUtil;
import com.valeriotor.acme.util.JWSUtil;
import com.valeriotor.acme.util.NonceUtil;
import fi.iki.elonen.NanoHTTPD;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.BrokenBarrierException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;

public class App {

    private static List<HTTPServerManager> servers = new ArrayList<>();
    private static HTTPChallengeServer httpChallengeServer;


    public static void main(String[] args) throws InterruptedException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, IOException, CertificateException, KeyStoreException, KeyManagementException, BrokenBarrierException {
        Security.addProvider(new BouncyCastleProvider());
        trustCertificate();
        initializeObjects(args);
        startServers();
        createAccount();
        AcmeOrder order = createOrder();
        Challenge challenge = getChallenge(order);
        beginChallenge(challenge);
        JWSUtil jwsUtil = JWSUtil.getInstance();
        String s = jwsUtil.flattenedSignedJson(jwsUtil.generateProtectedHeaderKid(order.getAuthorizations().get(0)), "");
        Thread.sleep(2000);
        HttpResponse<String> send = HTTPUtil.postRequest(order.getAuthorizations().get(0), s);
    }

    private static void initializeObjects(String[] args) throws IOException, InterruptedException, NoSuchAlgorithmException {
        ArgumentParser.tryCreateInstance(args);
        AcmeDirContainer.tryCreateInstance();
        NonceUtil.tryCreateInstance();
        JWSUtil.tryCreateInstance();
    }

    private static void startServers() throws IOException, BrokenBarrierException, InterruptedException {
        CyclicBarrier barrier = new CyclicBarrier(3);
        httpChallengeServer = new HTTPChallengeServer(5002);
        HTTPServerManager challengeServer = new HTTPServerManager(httpChallengeServer, barrier);
        HTTPServerManager shutdownServer = new HTTPServerManager(new HTTPShutdownServer(5003, App::stopServers), barrier);
        servers.add(challengeServer);
        servers.add(shutdownServer);
        new Thread(challengeServer).start();
        new Thread(shutdownServer).start();
        barrier.await();
    }

    private static void createAccount() throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, IOException, InterruptedException {
        String payload = "{\n" +
                "       \"termsOfServiceAgreed\": true,\n" + //maybe comment this out?
                "       \"contact\": [\n" +
                "         \"mailto:vtorsiello@student.ethz.ch\"\n" +
                "       ]\n" +
                "     }";

        JWSUtil jwsUtil = JWSUtil.getInstance();
        AcmeDirContainer dirContainer = AcmeDirContainer.getInstance();
        String header = jwsUtil.generateProtectedHeaderJwk(dirContainer.getNewAccountUrl());
        String toSend = jwsUtil.flattenedSignedJson(header, payload);

        HttpResponse<String> send = HTTPUtil.postRequest(dirContainer.getNewAccountUrl(), toSend);
        AccountManager.tryCreateInstance(send);
    }

    private static AcmeOrder createOrder() throws IOException, InterruptedException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        StringBuilder sb = new StringBuilder();
        for (String domain : ArgumentParser.getInstance().getDomains()) {
            Identifier i = new Identifier(domain);
            sb.append(i);
            sb.append(',');
        }
        sb.deleteCharAt(sb.length() - 1);

        String payload = "{\"identifiers\":[" + sb + "]}";
        JWSUtil jwsUtil = JWSUtil.getInstance();
        AcmeDirContainer dirContainer = AcmeDirContainer.getInstance();
        String header = jwsUtil.generateProtectedHeaderKid(dirContainer.getNewOrderUrl());
        String message = jwsUtil.flattenedSignedJson(header, payload);

        HttpResponse<String> send = HTTPUtil.postRequest(dirContainer.getNewOrderUrl(), message);
        return new AcmeOrder(send.body());
    }

    private static Challenge getChallenge(AcmeOrder order) throws IOException, InterruptedException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        JWSUtil jwsUtil = JWSUtil.getInstance();
        String s = jwsUtil.flattenedSignedJson(jwsUtil.generateProtectedHeaderKid(order.getAuthorizations().get(0)), "");
        HttpResponse<String> send = HTTPUtil.postRequest(order.getAuthorizations().get(0), s);
        JsonReader reader = Json.createReader(new StringReader(send.body()));
        JsonObject object = reader.readObject();
        JsonArray challenges = object.getJsonArray("challenges");
        List<Challenge> challengeList = challenges.getValuesAs(Challenge::new);
        ChallengeType challengeType = ArgumentParser.getInstance().getChallenge();
        for (Challenge c : challengeList) {
            if (c.getType() == challengeType) {
                return c;
            }
        }
        return null;
    }

    private static void beginChallenge(Challenge challenge) throws NoSuchAlgorithmException, IOException, InterruptedException, SignatureException, InvalidKeyException {
        if (challenge.getType() == ChallengeType.HTTPS) {
            JWSUtil jwsUtil = JWSUtil.getInstance();
            httpChallengeServer.setKeyAuthorization(jwsUtil.generateKeyAuthorization(challenge.getToken()));
            String message = jwsUtil.flattenedSignedJson(jwsUtil.generateProtectedHeaderKid(challenge.getUrl()), "{}");
            HttpResponse<String> response = HTTPUtil.postRequest(challenge.getUrl(), message);
        }
    }

    private static void trustCertificate() throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, KeyManagementException {
        String certificateString = readCertificate();
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        Certificate certificate = null;
        try (ByteArrayInputStream certificateStream = new ByteArrayInputStream(Base64.getDecoder().decode(certificateString))) {
            certificate = certificateFactory.generateCertificate(certificateStream);
        }

        KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
        char[] password = "perrig".toCharArray();
        store.load(null, password);
        store.setCertificateEntry("pebble", certificate);

        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(store);
        TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();


        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustManagers, null);
        SSLContext.setDefault(sslContext);
    }

    private static final boolean DEBUG = false;
    private static String readCertificate() throws IOException {
        List<String> strings;
        if(DEBUG)
            strings = Files.readAllLines(Path.of("/home/valeriotor/go/pkg/mod/github.com/letsencrypt/pebble@v1.0.1/test/certs/pebble.minica.pem"));
        else
            strings = Files.readAllLines(Path.of("pebble.minica.pem"));
        strings.remove(0);
        strings.remove(strings.size()-1);
        return String.join("", strings);
    }


    private static void stopServers() {
        try {
            Thread.sleep(700);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        servers.forEach(HTTPServerManager::stop);
    }

    public static class HTTPServerManager implements Runnable{
        private final NanoHTTPD server;
        private final CyclicBarrier barrier;
        private final CountDownLatch latch = new CountDownLatch(1);

        public HTTPServerManager(NanoHTTPD server, CyclicBarrier barrier) {
            this.server = server;
            this.barrier = barrier;
        }

        @Override
        public void run() {
            try {
                server.start();
                barrier.await();
                latch.await();
                server.stop();
            } catch (IOException | InterruptedException | BrokenBarrierException e) {
                e.printStackTrace();
            }
        }

        public void stop() {
            latch.countDown();
        }

    }




}
