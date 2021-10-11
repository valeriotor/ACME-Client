package com.valeriotor.acme.http;

import fi.iki.elonen.NanoHTTPD;

import java.io.IOException;
import java.util.concurrent.BrokenBarrierException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;

public class HTTPServerManager implements Runnable {
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
            if (barrier != null)
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
