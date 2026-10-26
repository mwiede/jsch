package com.jcraft.jsch;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.command.Command;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

class ChannelInputStreamFlowControlTest {
  @Test
  @Timeout(30)
  void closeInputReleasesUnreadBytesAndChannel() throws Exception {
    closeUnreadStream(false);
  }

  @Test
  @Timeout(30)
  void interruptedConsumerClosesUnreadBytesAndChannel() throws Exception {
    closeUnreadStream(true);
  }

  private static void closeUnreadStream(boolean interruptConsumer) throws Exception {
    int window = 64 * 1024;
    CountDownLatch payloadWritten = new CountDownLatch(1);
    CountDownLatch finish = new CountDownLatch(1);
    CountDownLatch remoteClosed = new CountDownLatch(1);
    java.util.concurrent.atomic.AtomicInteger closes =
        new java.util.concurrent.atomic.AtomicInteger();
    AtomicReference<Throwable> failure = new AtomicReference<>();
    List<String> commands = new CopyOnWriteArrayList<>();
    java.util.Set<Thread> before = Thread.getAllStackTraces().keySet();
    SshServer server = server();
    server.setCommandFactory((channel, name) -> {
      if (name.equals("stream"))
        channel.addChannelListener(new org.apache.sshd.common.channel.ChannelListener() {
          public void channelClosed(org.apache.sshd.common.channel.Channel closed,
              Throwable reason) {
            closes.incrementAndGet();
            remoteClosed.countDown();
          }
        });
      return command(name, commands, (output, error) -> {
        output.write(new byte[window]);
        output.flush();
        payloadWritten.countDown();
        finish.await();
      }, failure);
    });
    Session session = null;
    Thread consumer = null;
    try {
      server.start();
      session = connect(server);
      session.setConfig("max_input_buffer_size", Integer.toString(window));
      ChannelExec stream = (ChannelExec) session.openChannel("exec");
      stream.setLocalWindowSizeMax(window);
      stream.setCommand("stream");
      InputStream input = stream.getInputStream();
      stream.connect(1000);
      assertTrue(payloadWritten.await(10, TimeUnit.SECONDS));
      // A completed sibling proves all preceding DATA reached its receive sink.
      ChannelExec sibling = (ChannelExec) session.openChannel("exec");
      sibling.setCommand("sibling-before-close");
      InputStream siblingInput = sibling.getInputStream();
      sibling.connect(1000);
      while (siblingInput.read() >= 0) {
      }
      siblingInput.close();
      assertEquals(window, input.available());
      if (interruptConsumer) {
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch held = new CountDownLatch(1);
        consumer = new Thread(() -> {
          try {
            entered.countDown();
            held.await();
          } catch (InterruptedException expected) {
            // This is the cancellation requested by the test. The consumer's
            // ordinary resource cleanup below still closes its owned stream.
            Thread.currentThread().interrupt();
          } finally {
            try {
              input.close();
            } catch (Exception e) {
              failure.set(e);
            }
          }
        }, "cancelled-stream-consumer");
        consumer.setDaemon(true);
        consumer.start();
        assertTrue(entered.await(10, TimeUnit.SECONDS));
        consumer.interrupt();
        consumer.join(10000);
        assertFalse(consumer.isAlive());
      } else {
        input.close();
      }
      assertTrue(remoteClosed.await(10, TimeUnit.SECONDS),
          "Closing an unread input must close its channel and release retained DATA");
      input.close();
      stream.disconnect();
      assertEquals(1, closes.get());
      assertEquals("SSH channel input stream is closed",
          assertThrows(java.io.IOException.class, () -> input.read()).getMessage());
      ChannelExec after = (ChannelExec) session.openChannel("exec");
      after.setCommand("sibling-after-close");
      InputStream afterInput = after.getInputStream();
      after.connect(1000);
      while (afterInput.read() >= 0) {
      }
      afterInput.close();
      assertTrue(session.isConnected());
    } finally {
      finish.countDown();
      if (session != null)
        session.disconnect();
      if (consumer != null) {
        consumer.interrupt();
        consumer.join(10000);
      }
      server.stop(true);
      for (Thread thread : Thread.getAllStackTraces().keySet()) {
        if (!before.contains(thread) && (thread.getName().startsWith("Connect thread ")
            || thread.getName().equals("flow-control-server-command"))) {
          thread.join(10000);
          assertFalse(thread.isAlive(), "Owned SSH thread must terminate: " + thread.getName());
        }
      }
    }
  }

  @Test
  @Timeout(30)
  void heldConsumerDoesNotBlockTwoSiblingExecs() throws Exception {
    byte[] payload = new byte[128 * 1024];
    for (int i = 0; i < payload.length; i++)
      payload[i] = (byte) (i % 251);
    CountDownLatch consumerEntered = new CountDownLatch(1);
    CountDownLatch releaseConsumer = new CountDownLatch(1);
    CountDownLatch payloadWritten = new CountDownLatch(1);
    CountDownLatch finish = new CountDownLatch(1);
    AtomicReference<Throwable> failure = new AtomicReference<>();
    List<String> commands = new CopyOnWriteArrayList<>();
    ByteArrayOutputStream received = new ByteArrayOutputStream();
    SshServer server = server();
    server.setCommandFactory((channel, command) -> command(command, commands, (output, error) -> {
      output.write(1);
      output.flush();
      assertTrue(consumerEntered.await(10, TimeUnit.SECONDS));
      output.write(payload);
      output.flush();
      payloadWritten.countDown();
      assertTrue(finish.await(10, TimeUnit.SECONDS));
    }, failure));
    Session session = null;
    Thread consumer = null;
    try {
      server.start();
      session = connect(server);
      ChannelExec stream = (ChannelExec) session.openChannel("exec");
      stream.setCommand("stream");
      InputStream input = stream.getInputStream();
      stream.connect(1000);
      consumer = new Thread(() -> {
        try {
          assertEquals(1, input.read());
          consumerEntered.countDown();
          assertTrue(releaseConsumer.await(10, TimeUnit.SECONDS));
          byte[] buffer = new byte[8192];
          int n;
          while ((n = input.read(buffer)) >= 0)
            received.write(buffer, 0, n);
        } catch (Throwable e) {
          failure.compareAndSet(null, e);
        }
      }, "held-channel-consumer");
      consumer.setDaemon(true);
      consumer.start();
      assertTrue(payloadWritten.await(10, TimeUnit.SECONDS));
      AtomicReference<Throwable> openFailure = new AtomicReference<>();
      for (int i = 0; i < 2; i++) {
        ChannelExec sibling = (ChannelExec) session.openChannel("exec");
        try {
          sibling.setCommand("sibling-" + i);
          InputStream siblingInput = sibling.getInputStream();
          sibling.connect(1000);
          while (siblingInput.read() >= 0) {
          }
          siblingInput.close();
        } catch (Throwable e) {
          openFailure.compareAndSet(null, e);
        } finally {
          sibling.disconnect();
        }
      }
      releaseConsumer.countDown();
      finish.countDown();
      consumer.join(10000);
      assertFalse(consumer.isAlive());
      assertNull(failure.get(), () -> String.valueOf(failure.get()));
      assertArrayEquals(payload, received.toByteArray());
      assertNull(openFailure.get(), "Two sibling opens must complete while the consumer is held");
      assertEquals(Arrays.asList("stream", "sibling-0", "sibling-1"), commands);
      input.close();
    } finally {
      releaseConsumer.countDown();
      finish.countDown();
      if (session != null)
        session.disconnect();
      if (consumer != null) {
        consumer.interrupt();
        consumer.join(10000);
      }
      server.stop(true);
    }
  }

  @Test
  @Timeout(30)
  void receiveCreditIsReturnedOnlyForConsumedBytes() throws Exception {
    int window = 64 * 1024;
    byte[] payload = new byte[window];
    for (int i = 0; i < payload.length; i++)
      payload[i] = (byte) (i % 251);
    CountDownLatch payloadWritten = new CountDownLatch(1);
    CountDownLatch finish = new CountDownLatch(1);
    AtomicReference<Throwable> failure = new AtomicReference<>();
    AtomicReference<ChannelSession> remote = new AtomicReference<>();
    List<String> commands = new CopyOnWriteArrayList<>();
    SshServer server = server();
    server.setCommandFactory((channel, command) -> {
      if (command.equals("stream"))
        remote.set(channel);
      return command(command, commands, (output, error) -> {
        output.write(payload);
        output.flush();
        payloadWritten.countDown();
        assertTrue(finish.await(10, TimeUnit.SECONDS));
      }, failure);
    });
    Session session = null;
    try {
      server.start();
      session = connect(server);
      // Equal pipe/window sizes let the old implementation deliver all DATA, so this
      // test separates consumption-based credit from merely choosing a larger pipe.
      session.setConfig("max_input_buffer_size", Integer.toString(window));
      ChannelExec stream = (ChannelExec) session.openChannel("exec");
      stream.setLocalWindowSizeMax(window);
      stream.setCommand("stream");
      InputStream input = stream.getInputStream();
      stream.connect(1000);
      assertTrue(payloadWritten.await(10, TimeUnit.SECONDS));
      ChannelExec sibling = (ChannelExec) session.openChannel("exec");
      try {
        sibling.setCommand("sibling");
        InputStream siblingInput = sibling.getInputStream();
        sibling.connect(1000);
        while (siblingInput.read() >= 0) {
        }
        siblingInput.close();
        assertEquals(window, input.available());
        assertEquals(0, remote.get().getRemoteWindow().getSize(),
            "Delivery into an unread buffer must not grant more receive credit");
      } finally {
        sibling.disconnect();
      }
      finish.countDown();
      ByteArrayOutputStream received = new ByteArrayOutputStream();
      byte[] buffer = new byte[8192];
      int n;
      while ((n = input.read(buffer)) >= 0)
        received.write(buffer, 0, n);
      assertArrayEquals(payload, received.toByteArray());
      input.close();
      assertNull(failure.get(), () -> String.valueOf(failure.get()));
    } finally {
      finish.countDown();
      if (session != null)
        session.disconnect();
      server.stop(true);
    }
  }

  @Test
  @Timeout(30)
  void stdoutAndStderrShareCreditAndDrainAcrossBufferWraps() throws Exception {
    int window = 64 * 1024;
    byte[] first = new byte[window / 2];
    byte[] next = new byte[window / 4];
    Arrays.fill(first, (byte) 17);
    Arrays.fill(next, (byte) 29);
    CountDownLatch full = new CountDownLatch(1);
    CountDownLatch resume = new CountDownLatch(1);
    AtomicReference<Throwable> failure = new AtomicReference<>();
    AtomicReference<ChannelSession> remote = new AtomicReference<>();
    List<String> commands = new CopyOnWriteArrayList<>();
    SshServer server = server();
    server.setCommandFactory((channel, name) -> {
      if (name.equals("stream"))
        remote.set(channel);
      return command(name, commands, (output, error) -> {
        output.write(first);
        output.flush();
        error.write(first);
        error.flush();
        full.countDown();
        assertTrue(resume.await(10, TimeUnit.SECONDS));
        for (int i = 0; i < 5; i++) {
          output.write(next);
          output.flush();
          error.write(next);
          error.flush();
        }
      }, failure);
    });
    Session session = null;
    Thread errorReader = null;
    ByteArrayOutputStream stdout = new ByteArrayOutputStream();
    ByteArrayOutputStream stderr = new ByteArrayOutputStream();
    try {
      server.start();
      session = connect(server);
      session.setConfig("max_input_buffer_size", Integer.toString(window));
      ChannelExec stream = (ChannelExec) session.openChannel("exec");
      stream.setLocalWindowSizeMax(window);
      stream.setCommand("stream");
      InputStream input = stream.getInputStream();
      InputStream error = stream.getExtInputStream();
      stream.connect(1000);
      assertTrue(full.await(10, TimeUnit.SECONDS));
      ChannelExec fence = (ChannelExec) session.openChannel("exec");
      fence.setCommand("sibling");
      InputStream fenceInput = fence.getInputStream();
      fence.connect(1000);
      while (fenceInput.read() >= 0) {
      }
      fenceInput.close();
      assertEquals(window, input.available() + error.available());
      assertEquals(0, remote.get().getRemoteWindow().getSize(),
          "Stdout and stderr must share one consumption-based receive window");
      errorReader = new Thread(() -> {
        try {
          drain(error, stderr);
        } catch (Throwable e) {
          failure.compareAndSet(null, e);
        }
      }, "extended-stream-consumer");
      errorReader.setDaemon(true);
      errorReader.start();
      resume.countDown();
      drain(input, stdout);
      errorReader.join(10000);
      assertFalse(errorReader.isAlive());
      ByteArrayOutputStream expected = new ByteArrayOutputStream();
      expected.write(first);
      for (int i = 0; i < 5; i++)
        expected.write(next);
      assertArrayEquals(expected.toByteArray(), stdout.toByteArray());
      assertArrayEquals(expected.toByteArray(), stderr.toByteArray());
      assertNull(failure.get(), () -> String.valueOf(failure.get()));
      input.close();
      error.close();
    } finally {
      resume.countDown();
      if (session != null)
        session.disconnect();
      if (errorReader != null) {
        errorReader.interrupt();
        errorReader.join(10000);
      }
      server.stop(true);
    }
  }

  @Test
  @Timeout(30)
  void closingCompletedStdoutPreservesUnreadStderr() throws Exception {
    byte[] payload = new byte[128 * 1024];
    Arrays.fill(payload, (byte) 37);
    AtomicReference<Throwable> failure = new AtomicReference<>();
    List<String> commands = new CopyOnWriteArrayList<>();
    SshServer server = server();
    server.setCommandFactory((channel, name) -> command(name, commands, (output, error) -> {
      output.write(1);
      output.flush();
      error.write(payload);
      error.flush();
    }, failure));
    Session session = null;
    try {
      server.start();
      session = connect(server);
      // The baseline must also hold this complete final stream without blocking.
      session.setConfig("max_input_buffer_size", Integer.toString(256 * 1024));
      ChannelExec stream = (ChannelExec) session.openChannel("exec");
      stream.setCommand("stream");
      InputStream input = stream.getInputStream();
      InputStream error = stream.getExtInputStream();
      stream.connect(1000);
      assertEquals(1, input.read());
      assertEquals(-1, input.read());
      input.close();
      ByteArrayOutputStream received = new ByteArrayOutputStream();
      drain(error, received);
      assertArrayEquals(payload, received.toByteArray());
      assertNull(failure.get(), () -> String.valueOf(failure.get()));
      error.close();
    } finally {
      if (session != null)
        session.disconnect();
      server.stop(true);
    }
  }

  @Test
  @Timeout(30)
  void stderrConsumerCloseDoesNotEndTheSessionReader() throws Exception {
    AtomicReference<Throwable> failure = new AtomicReference<>();
    java.util.concurrent.atomic.AtomicBoolean readerEnded =
        new java.util.concurrent.atomic.AtomicBoolean();
    List<String> commands = new CopyOnWriteArrayList<>();
    SshServer server = server();
    server.setCommandFactory((channel, name) -> command(name, commands, (output, error) -> {
      output.write(1);
      output.flush();
      error.write(2);
      error.flush();
    }, failure));
    Session session = null;
    try {
      server.start();
      session = connect(server);
      session.setLogger(new Logger() {
        public boolean isEnabled(int level) {
          return true;
        }

        public void log(int level, String message) {
          if (message.startsWith("Caught an exception, leaving main loop"))
            readerEnded.set(true);
        }
      });
      ChannelExec stream = (ChannelExec) session.openChannel("exec");
      stream.setCommand("stream");
      InputStream input = stream.getInputStream();
      stream.setExtOutputStream(new OutputStream() {
        public void write(int value) throws java.io.IOException {
          throw new java.io.IOException("Requested stderr consumer close");
        }

        public void write(byte[] bytes, int offset, int length) throws java.io.IOException {
          throw new java.io.IOException("Requested stderr consumer close");
        }
      });
      stream.connect(1000);
      try {
        while (input.read() >= 0) {
        }
      } catch (java.io.IOException closedChannel) {
        assertEquals("SSH channel input stream is closed", closedChannel.getMessage());
      }
      // In the old path the reader logs its failure before closing stdout. The
      // terminal stdout read is therefore an ordering fence, not a timed probe.
      assertFalse(readerEnded.get(), "A stopped stderr consumer must close only its channel");
      assertTrue(session.isConnected());
      for (int i = 0; i < 2; i++) {
        ChannelExec sibling = (ChannelExec) session.openChannel("exec");
        sibling.setCommand("sibling-" + i);
        InputStream siblingInput = sibling.getInputStream();
        sibling.connect(1000);
        while (siblingInput.read() >= 0) {
        }
        siblingInput.close();
      }
      input.close();
    } finally {
      if (session != null)
        session.disconnect();
      server.stop(true);
    }
  }

  @Test
  @Timeout(30)
  void heldCreditWriteDoesNotHoldTheChannelReaderMonitor() throws Exception {
    int window = 64 * 1024;
    CountDownLatch full = new CountDownLatch(1);
    CountDownLatch finish = new CountDownLatch(1);
    CountDownLatch creditWriteEntered = new CountDownLatch(1);
    CountDownLatch releaseCreditWrite = new CountDownLatch(1);
    CountDownLatch sendSiblingData = new CountDownLatch(1);
    CountDownLatch siblingDataRead = new CountDownLatch(1);
    AtomicReference<Throwable> failure = new AtomicReference<>();
    AtomicReference<ChannelSession> remote = new AtomicReference<>();
    List<String> commands = new CopyOnWriteArrayList<>();
    SshServer server = server();
    server.setCommandFactory((channel, name) -> {
      if (name.equals("stream")) {
        remote.set(channel);
        return command(name, commands, (output, error) -> {
          output.write(new byte[window]);
          output.flush();
          full.countDown();
          finish.await();
        }, failure);
      }
      return new Command() {
        OutputStream output;
        org.apache.sshd.server.ExitCallback exit;
        Thread worker;

        public void setInputStream(InputStream input) {}

        public void setOutputStream(OutputStream output) {
          this.output = output;
        }

        public void setErrorStream(OutputStream error) {}

        public void setExitCallback(org.apache.sshd.server.ExitCallback exit) {
          this.exit = exit;
        }

        public void start(ChannelSession channel, org.apache.sshd.server.Environment environment) {
          worker = new Thread(() -> {
            try {
              assertTrue(sendSiblingData.await(10, TimeUnit.SECONDS));
              output.write(7);
              output.flush();
              exit.onExit(0);
            } catch (Throwable e) {
              failure.compareAndSet(null, e);
            }
          }, "flow-control-server-command");
          worker.setDaemon(true);
          worker.start();
        }

        public void destroy(ChannelSession channel) throws Exception {
          sendSiblingData.countDown();
          if (worker != null && worker != Thread.currentThread()) {
            worker.interrupt();
            worker.join(10000);
          }
        }
      };
    });
    SocketFactory sockets = new SocketFactory() {
      public java.net.Socket createSocket(String host, int port) throws java.io.IOException {
        return new java.net.Socket(host, port);
      }

      public InputStream getInputStream(java.net.Socket socket) throws java.io.IOException {
        return socket.getInputStream();
      }

      public OutputStream getOutputStream(java.net.Socket socket) throws java.io.IOException {
        return new java.io.FilterOutputStream(socket.getOutputStream()) {
          public void write(byte[] bytes, int offset, int length) throws java.io.IOException {
            if (Thread.currentThread().getName().equals("held-credit-writer")) {
              creditWriteEntered.countDown();
              try {
                releaseCreditWrite.await();
              } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new java.io.InterruptedIOException("Credit writer was interrupted");
              }
            }
            out.write(bytes, offset, length);
          }
        };
      }
    };
    Session session = null;
    Thread consumer = null;
    Thread siblingReader = null;
    try {
      server.start();
      session = connect(server, sockets);
      ChannelExec stream = (ChannelExec) session.openChannel("exec");
      stream.setLocalWindowSizeMax(window);
      stream.setCommand("stream");
      InputStream input = stream.getInputStream();
      stream.connect(1000);
      assertTrue(full.await(10, TimeUnit.SECONDS));
      ChannelExec sibling = (ChannelExec) session.openChannel("exec");
      sibling.setCommand("waiting-sibling");
      InputStream siblingInput = sibling.getInputStream();
      sibling.connect(1000);
      assertEquals(window, input.available());
      consumer = new Thread(() -> {
        try {
          assertEquals(window / 2, input.read(new byte[window / 2]));
        } catch (Throwable e) {
          failure.compareAndSet(null, e);
        }
      }, "held-credit-writer");
      consumer.setDaemon(true);
      consumer.start();
      assertTrue(creditWriteEntered.await(10, TimeUnit.SECONDS));
      org.apache.sshd.common.util.buffer.Buffer adjustment = remote.get().getSession()
          .createBuffer(org.apache.sshd.common.SshConstants.SSH_MSG_CHANNEL_WINDOW_ADJUST, 16);
      adjustment.putInt(remote.get().getRecipient());
      adjustment.putUInt(1);
      assertTrue(remote.get().getSession().writePacket(adjustment).await(10000));
      sendSiblingData.countDown();
      siblingReader = new Thread(() -> {
        try {
          assertEquals(7, siblingInput.read());
          siblingDataRead.countDown();
        } catch (Throwable e) {
          failure.compareAndSet(null, e);
        }
      }, "sibling-data-consumer");
      siblingReader.setDaemon(true);
      siblingReader.start();
      assertTrue(siblingDataRead.await(10, TimeUnit.SECONDS),
          "The reader must process sibling DATA while consumption credit is waiting on its socket");
      releaseCreditWrite.countDown();
      consumer.join(10000);
      siblingReader.join(10000);
      assertFalse(consumer.isAlive());
      assertFalse(siblingReader.isAlive());
      assertNull(failure.get(), () -> String.valueOf(failure.get()));
      finish.countDown();
      input.close();
      siblingInput.close();
    } finally {
      releaseCreditWrite.countDown();
      sendSiblingData.countDown();
      finish.countDown();
      if (session != null)
        session.disconnect();
      if (consumer != null) {
        consumer.interrupt();
        consumer.join(10000);
      }
      if (siblingReader != null) {
        siblingReader.interrupt();
        siblingReader.join(10000);
      }
      server.stop(true);
    }
  }

  private static void drain(InputStream input, ByteArrayOutputStream received) throws Exception {
    byte[] bytes = new byte[8192];
    int count;
    while ((count = input.read(bytes)) >= 0)
      received.write(bytes, 0, count);
  }

  private static SshServer server() throws Exception {
    SshServer server = SshServer.setUpDefaultServer();
    server.setPort(0);
    SimpleGeneratorHostKeyProvider keys = new SimpleGeneratorHostKeyProvider();
    keys.setKeySpec(new ECGenParameterSpec("secp256r1"));
    keys.loadKeys(null);
    server.setKeyPairProvider(keys);
    server.setPasswordAuthenticator((user, password, session) -> true);
    return server;
  }

  private static Session connect(SshServer server) throws Exception {
    return connect(server, null);
  }

  private static Session connect(SshServer server, SocketFactory sockets) throws Exception {
    Session session = new JSch().getSession("test", "127.0.0.1", server.getPort());
    if (sockets != null)
      session.setSocketFactory(sockets);
    session.setPassword("test");
    session.setConfig("StrictHostKeyChecking", "no");
    session.setConfig("kex", "ecdh-sha2-nistp256");
    session.setConfig("CheckKexes", "ecdh-sha2-nistp256");
    session.connect(10000);
    return session;
  }

  private interface Writer {
    void write(OutputStream output, OutputStream error) throws Exception;
  }

  private static Command command(String name, List<String> commands, Writer writer,
      AtomicReference<Throwable> failure) {
    return new Command() {
      OutputStream output;
      OutputStream error;
      org.apache.sshd.server.ExitCallback exit;
      Thread worker;

      public void setInputStream(InputStream input) {}

      public void setOutputStream(OutputStream output) {
        this.output = output;
      }

      public void setErrorStream(OutputStream error) {
        this.error = error;
      }

      public void setExitCallback(org.apache.sshd.server.ExitCallback exit) {
        this.exit = exit;
      }

      public void start(ChannelSession channel, org.apache.sshd.server.Environment environment) {
        commands.add(name);
        worker = new Thread(() -> {
          try {
            if (name.equals("stream"))
              writer.write(output, error);
            else {
              output.write(name.getBytes(StandardCharsets.UTF_8));
              output.flush();
            }
            exit.onExit(0);
          } catch (Throwable e) {
            failure.compareAndSet(null, e);
          }
        }, "flow-control-server-command");
        worker.setDaemon(true);
        worker.start();
      }

      public void destroy(ChannelSession channel) throws Exception {
        if (worker != null && worker != Thread.currentThread()) {
          worker.interrupt();
          worker.join(10000);
        }
      }
    };
  }
}
