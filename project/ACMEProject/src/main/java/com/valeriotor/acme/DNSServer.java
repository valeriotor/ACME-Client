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
    private String textChallenge; //todo: might want to make this atomic/volatile
    private boolean running = true;

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
                System.out.println(packet.getAddress() + " " + packet.getPort());
                System.out.println(request);
                int type = request.getQuestion().getType();
                Header header = new Header(request.getHeader().getID());
                header.setFlag(Flags.RA);
                header.setFlag(Flags.QR);
                header.setFlag(Flags.AA);
                Message response = new Message();
                response.setHeader(header);

                response.addRecord(request.getQuestion(), Section.QUESTION);
                if (type == Type.A) {
                    response.addRecord(org.xbill.DNS.Record.fromString(request.getQuestion().getName(), Type.A, DClass.IN, 30, resultForAQuery, Name.root), Section.ANSWER);
                } else if (type == Type.TXT) {
                    response.addRecord(org.xbill.DNS.Record.fromString(request.getQuestion().getName(), Type.TXT, DClass.IN, 30, textChallenge, Name.root), Section.ANSWER);
                    App.beginPolling();
                }

                byte[] responseBytes = response.toWire(256);
                System.out.println(response);
                DatagramPacket responsePacket = new DatagramPacket(responseBytes, responseBytes.length, packet.getAddress(), packet.getPort());
                socket.send(responsePacket);
                System.out.println(responsePacket.getAddress() + " " + responsePacket.getPort());
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        socket.close();
    }

    public void setTextChallenge(String textChallenge) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(textChallenge.getBytes(StandardCharsets.UTF_8));
        this.textChallenge = new String(Base64.getUrlEncoder().withoutPadding().encode(hash));
    }
}
