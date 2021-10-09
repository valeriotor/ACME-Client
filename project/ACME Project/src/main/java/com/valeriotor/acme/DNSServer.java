package com.valeriotor.acme;

import org.xbill.DNS.*;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketException;

public class DNSServer extends Thread{
    private final DatagramSocket socket;
    private final String resultForAQuery;
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
                System.out.println("Received DNS packet, record type: " + request.getQuestion().getType());
                if (request.getQuestion().getType() == Type.A) {
                    Message response = new Message(request.getHeader().getID());
                    response.addRecord(request.getQuestion(), Section.QUESTION);
                    response.addRecord(Record.fromString(Name.root, Type.A, DClass.IN, 65536L, resultForAQuery, Name.root), Section.ANSWER);
                    byte[] responseBytes = response.toWire(512);
                    DatagramPacket responsePacket = new DatagramPacket(responseBytes, responseBytes.length, packet.getAddress(), packet.getPort());
                    socket.send(responsePacket);
                }

            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        socket.close();
    }
}
