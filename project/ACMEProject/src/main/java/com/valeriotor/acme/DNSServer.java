package com.valeriotor.acme;

import org.xbill.DNS.*;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class DNSServer extends Thread{
    private final DatagramSocket socket;
    private final String resultForAQuery;
    private String textChallenge;
    private boolean running = true;

    public DNSServer(int port) throws SocketException {
        this.socket = new DatagramSocket(port);
        resultForAQuery = ArgumentParser.getInstance().getDnsRecord();
        //setDaemon(true);
    }

    @Override
    public void run() {
        while (running) {
            byte[] buf = new byte[512];
            DatagramPacket packet = new DatagramPacket(buf, buf.length);
            try {
                socket.receive(packet);
                Message request = new Message(buf);
                System.out.println(request);
                int type = request.getQuestion().getType();
                Message response = new Message(request.getHeader().getID());
                response.addRecord(request.getQuestion(), Section.QUESTION);
                if (type == Type.A) {
                    response.addRecord(org.xbill.DNS.Record.fromString(request.getQuestion().getName(), Type.A, DClass.IN, 65536L, resultForAQuery, request.getQuestion().getName()), Section.ANSWER);
                    System.out.println(response);
                } else if (type == Type.TXT) {
                    response.addRecord(org.xbill.DNS.Record.fromString(request.getQuestion().getName(), Type.TXT, DClass.IN, 65536L, textChallenge, request.getQuestion().getName()), Section.ANSWER);
                    App.beginPolling();
                }
                byte[] responseBytes = response.toWire(512);
                DatagramPacket responsePacket = new DatagramPacket(responseBytes, responseBytes.length, packet.getAddress(), packet.getPort());
                socket.send(responsePacket);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        System.out.println("Closing DNS Socket");
        socket.close();
    }

    public void setTextChallenge(String textChallenge) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(textChallenge.getBytes(StandardCharsets.UTF_8));
        this.textChallenge = new String(Base64.getUrlEncoder().withoutPadding().encode(hash));
    }
}
