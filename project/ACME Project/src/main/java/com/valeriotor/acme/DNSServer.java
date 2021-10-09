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
    private int debugCounter = 0;

    public DNSServer(int port) throws SocketException {
        this.socket = new DatagramSocket(port);
        resultForAQuery = ArgumentParser.getInstance().getDnsRecord();
        setDaemon(true);
    }

    @Override
    public void run() {
        while (running) {
            byte[] buf = new byte[512];
            DatagramPacket packet = new DatagramPacket(buf, buf.length);
            try {
                socket.receive(packet);
                Message request = new Message(buf);
                int type = request.getQuestion().getType();
                System.out.println("Received DNS packet, record type: " + type);
                System.out.println("REQUEST: " + request);
                System.out.println("\n----------------------");
                Message response = new Message(request.getHeader().getID());
                response.addRecord(request.getQuestion(), Section.QUESTION);
                if (type == Type.A || type == Type.AAAA) {
                    response.addRecord(Record.fromString(request.getQuestion().getName(), Type.A, DClass.IN, 65536L, resultForAQuery, request.getQuestion().getName()), Section.ANSWER);
                } else if (type == Type.TXT) {
                    String textChallenge = this.textChallenge;
                    String name = request.getQuestion().getName().toString();
                    if (debugCounter == 0 || debugCounter == 1) {
                        if (name.charAt(name.length() - 1) == '.') {
                            name = name.substring(0, name.length()-1);
                        }
                    }
                    if (debugCounter == 1 || debugCounter == 2) {
                        MessageDigest digest = MessageDigest.getInstance("SHA-256");
                        byte[] hash = digest.digest(textChallenge.getBytes(StandardCharsets.UTF_8));
                        textChallenge = new String(Base64.getUrlEncoder().withoutPadding().encode(hash));
                    }
                    System.out.println(debugCounter);
                    debugCounter++;
                    response.addRecord(Record.fromString(request.getQuestion().getName(), Type.TXT, DClass.IN, 65536L, textChallenge, request.getQuestion().getName()), Section.ANSWER);
                }
                System.out.println("RESPONSE: " + response);
                System.out.println("\n----------------------");
                byte[] responseBytes = response.toWire(512);
                DatagramPacket responsePacket = new DatagramPacket(responseBytes, responseBytes.length, packet.getAddress(), packet.getPort());
                socket.send(responsePacket);
            } catch (IOException | NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        }
        socket.close();
    }

    public void setTextChallenge(String textChallenge) throws NoSuchAlgorithmException {
        /*MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(textChallenge.getBytes(StandardCharsets.UTF_8));
        this.textChallenge = new String(Base64.getUrlEncoder().withoutPadding().encode(hash));*/
        this.textChallenge = textChallenge;
    }
}
