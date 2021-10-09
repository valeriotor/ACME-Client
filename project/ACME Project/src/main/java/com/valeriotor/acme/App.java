package com.valeriotor.acme;

import com.valeriotor.acme.http.HTTPCertificateServer;
import com.valeriotor.acme.http.HTTPChallengeServer;
import com.valeriotor.acme.http.HTTPServerManager;
import com.valeriotor.acme.http.HTTPShutdownServer;
import com.valeriotor.acme.util.HTTPUtil;
import com.valeriotor.acme.util.JWSUtil;
import com.valeriotor.acme.util.NonceUtil;
import fi.iki.elonen.NanoHTTPD;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Scanner;
import java.util.concurrent.BrokenBarrierException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.stream.Collectors;

public class App {

    private static List<HTTPServerManager> servers = new ArrayList<>();
    private static HTTPChallengeServer httpChallengeServer;
    private static CountDownLatch beginPollLatch = new CountDownLatch(1);
    private static DNSServer dnsServer;
    private static KeyPair certificateKeyPair;


    public static void main(String[] args) throws InterruptedException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, IOException, CertificateException, KeyStoreException, KeyManagementException, BrokenBarrierException, NoSuchProviderException, OperatorCreationException, UnrecoverableKeyException {
        Security.addProvider(new BouncyCastleProvider());
        trustCertificate();
        initializeObjects(args);
        startServers();
        createAccount();
        AcmeOrder order = createOrder();
        List<Challenge> challenges = getChallenges(order);
        for (Challenge c : challenges) {
            beginChallenge(c);
            if (!pollAuthorizationResult(order)) {
                return;
            }
        }
        boolean orderFinalized = finalizeOrder(order);
        if (orderFinalized) {
            String certificateString = downloadCertificate(order);
            List<List<String>> certificateLines = new ArrayList<>();
            Scanner scanner = new Scanner(certificateString);
            while (scanner.hasNextLine()) {
                String line = scanner.nextLine();
                if (line.toLowerCase().contains("begin certificate")) {
                    certificateLines.add(new ArrayList<>());
                } else if (!line.toLowerCase().contains("end certificate")) {
                    certificateLines.get(certificateLines.size() - 1).add(line);
                }
            }
            List<Certificate> certificates = new ArrayList<>();
            for (List<String> l : certificateLines) {
                String join = String.join("", l);
                Certificate certificate1 = getCertificate(join);
                certificates.add(certificate1);
            }
            NanoHTTPD certificateServer = new HTTPCertificateServer(5001);
            KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
            char[] password = "perrig".toCharArray();
            store.load(null, password);
            store.setKeyEntry("main", certificateKeyPair.getPrivate(), password, certificates.toArray(new Certificate[]{}));
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
            tmf.init(store);
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            SSLContext tls = SSLContext.getInstance("TLS");
            keyManagerFactory.init(store, password);
            tls.init(keyManagerFactory.getKeyManagers(), tmf.getTrustManagers(), null);
            certificateServer.makeSecure(NanoHTTPD.makeSSLSocketFactory(store, keyManagerFactory.getKeyManagers()), null);

            //certificateServer.setServerSocketFactory(new NanoHTTPD.SecureServerSocketFactory(NanoHTTPD.makeSSLSocketFactory(store, keyManagerFactory), null));
            CyclicBarrier barrier = new CyclicBarrier(2);
            HTTPServerManager manager = new HTTPServerManager(certificateServer, barrier);
            servers.add(manager);
            new Thread(manager).start();
            barrier.await();
            if (ArgumentParser.getInstance().isRevoke()) {
                revokeCertificate(certificateLines);
            }
        }

    }

    private static void initializeObjects(String[] args) throws IOException, InterruptedException, NoSuchAlgorithmException {
        System.out.println("Initializing objects");
        ArgumentParser.tryCreateInstance(args);
        AcmeDirContainer.tryCreateInstance();
        NonceUtil.tryCreateInstance();
        JWSUtil.tryCreateInstance();
    }

    private static void startServers() throws IOException, BrokenBarrierException, InterruptedException {
        System.out.println("Starting servers");
        dnsServer = new DNSServer(10053);
        dnsServer.start();
        CyclicBarrier barrier = new CyclicBarrier(3);
        httpChallengeServer = new HTTPChallengeServer(5002);
        HTTPServerManager challengeServer = new HTTPServerManager(httpChallengeServer, barrier);
        HTTPServerManager shutdownServer = new HTTPServerManager(new HTTPShutdownServer(5003, App::stopServers), barrier);
        servers.add(challengeServer);
        servers.add(shutdownServer);
        Thread t1 = new Thread(challengeServer);t1.setDaemon(true);t1.start();
        Thread t2 = new Thread(shutdownServer);t2.setDaemon(true);t2.start();
        barrier.await();
    }

    private static void createAccount() throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, IOException, InterruptedException {
        System.out.println("Creating account");
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
        System.out.println("Creating order");
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
        return new AcmeOrder(send);
    }

    private static List<Challenge> getChallenges(AcmeOrder order) throws IOException, InterruptedException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        System.out.println("Getting challenges");
        List<Challenge> challenges = new ArrayList<>();
        JWSUtil jwsUtil = JWSUtil.getInstance();
        for (String auth : order.getAuthorizations()) {
            String s = jwsUtil.flattenedSignedJson(jwsUtil.generateProtectedHeaderKid(auth), "");
            HttpResponse<String> send = HTTPUtil.postRequest(auth, s);
            List<Challenge> challengeList = Challenge.getChallengesFromAuthorizationResponse(send);
            ChallengeType challengeType = ArgumentParser.getInstance().getChallenge();
            for (Challenge c : challengeList) {
                if (c.getType() == challengeType) {
                    challenges.add(c);
                }
            }
        }

        return challenges;
    }

    private static void beginChallenge(Challenge challenge) throws NoSuchAlgorithmException, IOException, InterruptedException, SignatureException, InvalidKeyException {
        System.out.println("Starting challenge");
        JWSUtil jwsUtil = JWSUtil.getInstance();
        if (challenge.getType() == ChallengeType.HTTPS) {
            httpChallengeServer.setKeyAuthorization(jwsUtil.generateKeyAuthorization(challenge.getToken()));
        } else if (challenge.getType() == ChallengeType.DNS) {
            dnsServer.setTextChallenge(jwsUtil.generateKeyAuthorization(challenge.getToken()));
        }
        String message = jwsUtil.flattenedSignedJson(jwsUtil.generateProtectedHeaderKid(challenge.getUrl()), "{}");
        HttpResponse<String> response = HTTPUtil.postRequest(challenge.getUrl(), message);
    }

    public static void beginPolling() {
        beginPollLatch.countDown();
    }

    private static boolean pollAuthorizationResult(AcmeOrder order) throws InterruptedException, IOException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        beginPollLatch.await();
        beginPollLatch = new CountDownLatch(1);
        JWSUtil jwsUtil = JWSUtil.getInstance();
        int maximumTries = 30;
        do {
            String s = jwsUtil.flattenedSignedJson(jwsUtil.generateProtectedHeaderKid(order.getAuthorizations().get(0)), "");
            HttpResponse<String> response = HTTPUtil.postRequest(order.getAuthorizations().get(0), s);
            List<Challenge> challengeList = Challenge.getChallengesFromAuthorizationResponse(response);
            Challenge challenge = null;
            for (Challenge c : challengeList) {
                if (c.getType() == ArgumentParser.getInstance().getChallenge()) {
                    challenge = c;
                    break;
                }
            }
            if (challenge != null && challenge.getStatus().equals("valid")) {
                return true;
            } else if (challenge == null || challenge.getStatus().equals("invalid")) {
                return false;
            }
            Thread.sleep(300);
        } while (maximumTries-- > 0);
        return false;
    }

    private static boolean finalizeOrder(AcmeOrder order) throws IOException, InterruptedException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, NoSuchProviderException, CertificateEncodingException, OperatorCreationException {
        System.out.println("Finalizing order");
        JWSUtil jwsUtil = JWSUtil.getInstance();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        certificateKeyPair = kpg.generateKeyPair();
        String name = "CN=Valerio, OU=IT, O=ETH, L=Zurich, ST=Switzerland, C=CH";
        X500Principal subject = new X500Principal(name);
        List<String> domains = ArgumentParser.getInstance().getDomains();
        ContentSigner signGen = new JcaContentSignerBuilder("SHA256withRSA").build(certificateKeyPair.getPrivate());
        PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(subject, certificateKeyPair.getPublic());
        List<GeneralName> generalNames = new ArrayList<>();
        for (String s : domains) {
            GeneralName generalName = new GeneralName(GeneralName.dNSName, s);
            generalNames.add(generalName);
        }
        ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
        GeneralNames generalNames1 = new GeneralNames(generalNames.toArray(new GeneralName[]{}));
        extensionsGenerator.addExtension(Extension.subjectAlternativeName, false, generalNames1);
        builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensionsGenerator.generate());
        PKCS10CertificationRequest request = builder.build(signGen);
        byte[] encoded = request.getEncoded();
        String s = new String(Base64.getUrlEncoder().withoutPadding().encode(encoded));
        String payload = "{\"csr\":\"" + s + "\"}";
        String url = order.getFinalize();
        String message = jwsUtil.flattenedSignedJson(jwsUtil.generateProtectedHeaderKid(url), payload);
        HttpResponse<String> response = HTTPUtil.postRequest(url, message);
        AcmeOrder finalizeResponse = new AcmeOrder(response);
        return !finalizeResponse.getStatus().equals("invalid");
    }

    private static String downloadCertificate(AcmeOrder order) throws InterruptedException, IOException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        System.out.println("Downloading certificate");
        JWSUtil jwsUtil = JWSUtil.getInstance();
        String url = order.getLocation();
        AcmeOrder finalOrder = null;
        do {
            Thread.sleep(1400);
            String message2 = jwsUtil.flattenedSignedJson(jwsUtil.generateProtectedHeaderKid(url), "");
            HttpResponse<String> response2 = HTTPUtil.postRequest(url, message2);
            finalOrder = new AcmeOrder(response2);
        } while (finalOrder.getCertificate() == null);
        url = finalOrder.getCertificate();
        String message3 = jwsUtil.flattenedSignedJson(jwsUtil.generateProtectedHeaderKid(url), "");
        HttpResponse<String> response3 = HTTPUtil.postRequest(url, message3);
        return response3.body();
    }

    private static void revokeCertificate(List<List<String>> certificateLines) throws IOException, InterruptedException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        JWSUtil jwsUtil = JWSUtil.getInstance();
        List<String> certificates = certificateLines.stream().map(l -> String.join("", l)).collect(Collectors.toList());
        String certificate0 = certificates.get(0);
        String certificate0urlEncoded = new String(Base64.getUrlEncoder().withoutPadding().encode(Base64.getDecoder().decode(certificate0.getBytes(StandardCharsets.UTF_8))));
        String url = AcmeDirContainer.getInstance().getRevokeCertificateUrl();
        String payload = "{\"certificate\":\"" + certificate0urlEncoded + "\"}";
        String message = jwsUtil.flattenedSignedJson(jwsUtil.generateProtectedHeaderKid(url), payload);
        HttpResponse<String> response = HTTPUtil.postRequest(url, message);
    }

    private static void trustCertificate() throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, KeyManagementException {
        String certificateString = readCertificate();
        Certificate certificate = getCertificate(certificateString);

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

    private static Certificate getCertificate(String certificateString) throws CertificateException, IOException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        Certificate certificate = null;
        try (ByteArrayInputStream certificateStream = new ByteArrayInputStream(Base64.getDecoder().decode(certificateString))) {
            certificate = certificateFactory.generateCertificate(certificateStream);
        }
        return certificate;
    }

    private static final boolean DEBUG = false;

    private static String readCertificate() throws IOException {
        List<String> strings;
        if (DEBUG)
            strings = Files.readAllLines(Path.of("/home/valeriotor/go/pkg/mod/github.com/letsencrypt/pebble@v1.0.1/test/certs/pebble.minica.pem"));
        else
            strings = Files.readAllLines(Path.of("pebble.minica.pem"));
        strings.remove(0);
        strings.remove(strings.size() - 1);
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

}
