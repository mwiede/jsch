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
  void heldConsumerDoesNotBlockTwoSiblingExecs() throws Exception {
    byte[] payload = new byte[128 * 1024];
    for (int i = 0; i < payload.length; i++) payload[i] = (byte) (i % 251);
    CountDownLatch consumerEntered = new CountDownLatch(1);
    CountDownLatch releaseConsumer = new CountDownLatch(1);
    CountDownLatch payloadWritten = new CountDownLatch(1);
    CountDownLatch finish = new CountDownLatch(1);
    AtomicReference<Throwable> failure = new AtomicReference<>();
    List<String> commands = new CopyOnWriteArrayList<>();
    ByteArrayOutputStream received = new ByteArrayOutputStream();
    SshServer server = server();
    server.setCommandFactory((channel, command) -> command(command, commands, output -> {
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
          while ((n = input.read(buffer)) >= 0) received.write(buffer, 0, n);
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
          while (siblingInput.read() >= 0) {}
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
      if (session != null) session.disconnect();
      if (consumer != null) { consumer.interrupt(); consumer.join(10000); }
      server.stop(true);
    }
  }

  @Test
  @Timeout(30)
  void receiveCreditIsReturnedOnlyForConsumedBytes() throws Exception {
    int window = 64 * 1024;
    byte[] payload = new byte[window];
    for (int i = 0; i < payload.length; i++) payload[i] = (byte) (i % 251);
    CountDownLatch payloadWritten = new CountDownLatch(1);
    CountDownLatch finish = new CountDownLatch(1);
    AtomicReference<Throwable> failure = new AtomicReference<>();
    AtomicReference<ChannelSession> remote = new AtomicReference<>();
    List<String> commands = new CopyOnWriteArrayList<>();
    SshServer server = server();
    server.setCommandFactory((channel, command) -> {
      if (command.equals("stream")) remote.set(channel);
      return command(command, commands, output -> {
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
        while (siblingInput.read() >= 0) {}
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
      while ((n = input.read(buffer)) >= 0) received.write(buffer, 0, n);
      assertArrayEquals(payload, received.toByteArray());
      input.close();
      assertNull(failure.get(), () -> String.valueOf(failure.get()));
    } finally {
      finish.countDown();
      if (session != null) session.disconnect();
      server.stop(true);
    }
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
    Session session = new JSch().getSession("test", "127.0.0.1", server.getPort());
    session.setPassword("test");
    session.setConfig("StrictHostKeyChecking", "no");
    session.setConfig("kex", "ecdh-sha2-nistp256");
    session.setConfig("CheckKexes", "ecdh-sha2-nistp256");
    session.connect(10000);
    return session;
  }

  private interface Writer { void write(OutputStream output) throws Exception; }

  private static Command command(String name, List<String> commands, Writer writer,
      AtomicReference<Throwable> failure) {
    return new Command() {
      OutputStream output;
      org.apache.sshd.server.ExitCallback exit;
      Thread worker;
      public void setInputStream(InputStream input) {}
      public void setOutputStream(OutputStream output) { this.output = output; }
      public void setErrorStream(OutputStream error) {}
      public void setExitCallback(org.apache.sshd.server.ExitCallback exit) { this.exit = exit; }
      public void start(ChannelSession channel, org.apache.sshd.server.Environment environment) {
        commands.add(name);
        worker = new Thread(() -> {
          try {
            if (name.equals("stream")) writer.write(output);
            else { output.write(name.getBytes(StandardCharsets.UTF_8)); output.flush(); }
            exit.onExit(0);
          } catch (Throwable e) { failure.compareAndSet(null, e); }
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
