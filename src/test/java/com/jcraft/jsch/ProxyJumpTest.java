package com.jcraft.jsch;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ThreadFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ProxyJumpTest {
  @TempDir
  Path tempDir;

  @Test
  void parsesHopChain() throws Exception {
    List<ProxyJump.Hop> hops = ProxyJump.parse("alice@corp@first:2222,ssh://bob@[::1]:2200,last");
    assertEquals(3, hops.size());
    assertEquals("alice@corp", hops.get(0).user);
    assertEquals("first", hops.get(0).host);
    assertEquals(2222, hops.get(0).port);
    assertEquals("bob", hops.get(1).user);
    assertEquals("::1", hops.get(1).host);
    assertEquals(2200, hops.get(1).port);
    assertEquals("last", hops.get(2).host);
    assertEquals(0, hops.get(2).port);
  }

  @Test
  void rejectsMalformedHops() {
    for (String value : new String[] {"", "a,,b", "a:", "a:0", "a:65536", "@a", "[::1",
        "ssh://host/path", "a b", "ssh://host:", "ssh://host?x", "ssh://host#x", "ssh://@host",
        "ssh://a:pw@host", "::1", "ssh://a%zz@host"}) {
      assertThrows(JSchException.class, () -> ProxyJump.parse(value), value);
    }
  }

  @Test
  void parsesUriLikeOpenSsh() throws Exception {
    List<ProxyJump.Hop> hops =
        ProxyJump.parse("ssh://a%40b;fingerprint=SHA256:x@bastion_1/,ssh://[fe80::1]");
    assertEquals("a@b", hops.get(0).user);
    assertEquals("bastion_1", hops.get(0).host);
    assertEquals(0, hops.get(0).port);
    assertEquals("fe80::1", hops.get(1).host);
  }

  @Test
  void parseErrorsNeverEchoPasswords() throws Exception {
    for (String value : new String[] {"ssh://alice:s3cret@host", "ssh://alice:s3cret@host:x",
        "alice:s3cret@host:bad"}) {
      JSchException error = assertThrows(JSchException.class, () -> ProxyJump.parse(value));
      assertFalse(error.getMessage().contains("s3cret"), error.getMessage());
      assertTrue(error.getMessage().contains("alice:***@host"), error.getMessage());
      assertEquals(null, error.getCause());
    }
    JSch jsch = new JSch();
    jsch.setConfigRepository(
        OpenSSHConfig.parse("Host target\n  ProxyJump ssh://alice:s3cret@host\n"));
    JSchException error = assertThrows(JSchException.class, () -> jsch.getSession("target"));
    assertFalse(error.getMessage().contains("s3cret"), error.getMessage());
    assertEquals("host", ProxyJump.redact("host"));
    assertEquals("alice@host:22", ProxyJump.redact("alice@host:22"));
  }

  @Test
  void configuresProxyForTargetButNotNone() throws Exception {
    JSch jsch = new JSch();
    jsch.setConfigRepository(OpenSSHConfig.parse(String.join("\n", "Host target",
        "  ProxyJump first,,second", "Host direct", "  ProxyJump none", "")));
    assertThrows(JSchException.class, () -> jsch.getSession("target"));
    assertNotNull(jsch.getSession("direct"));
  }

  @Test
  void detectsRecursiveJumpBeforeOpeningSocket() throws Exception {
    JSch jsch = new JSch();
    jsch.setConfigRepository(OpenSSHConfig.parse("Host loop\n  ProxyJump loop\n"));
    Session session = jsch.getSession("loop");
    JSchException error = assertThrows(JSchException.class, session::connect);
    assertEquals("ProxyJump cycle: loop -> loop", error.getMessage());
    error = assertThrows(JSchException.class, session::connect);
    assertEquals("ProxyJump cycle: loop -> loop", error.getMessage());
  }

  @Test
  void detectsIndirectJumpCycle() throws Exception {
    JSch jsch = new JSch();
    jsch.setConfigRepository(OpenSSHConfig.parse(String.join("\n", "Host a", "  User u",
        "  ProxyJump b", "Host b", "  User u", "  ProxyJump a", "")));
    Session session = jsch.getSession("a");
    JSchException error = assertThrows(JSchException.class, session::connect);
    assertEquals("ProxyJump cycle: b -> a -> b", error.getMessage());
  }

  @Test
  void jumpThroughHostThatJumpsBackToUnproxiedAliasIsNotACycle() throws Exception {
    // With an explicit proxy the target's own config is not part of the chain: b jumps through a,
    // whose config has no ProxyJump, so the chain ends there.
    int port = closedPort();
    JSch jsch = new JSch();
    jsch.setConfigRepository(OpenSSHConfig.parse(String.join("\n", "Host a", "  User u",
        "  HostName 127.0.0.1", "  Port " + port, "Host b", "  User u", "  ProxyJump a", "")));
    Session target = jsch.getSession("u", "a");
    target.setProxy(new ProxyJump(target, "b"));
    JSchException error = assertThrows(JSchException.class, () -> target.connect(2000));
    assertFalse(error.getMessage().contains("cycle"), error.getMessage());
  }

  @Test
  void throughRequiresConnectedHopAndClosesNothingItDoesNotOwn() throws Exception {
    JSch jsch = new JSch();
    Session hop = jsch.getSession("u", "hop");
    Session target = jsch.getSession("u", "target");
    target.setProxy(ProxyJump.through(hop));
    JSchException error = assertThrows(JSchException.class, () -> target.connect(1000));
    assertTrue(error.getMessage().contains("hop hop is not connected"), error.getMessage());
    assertThrows(NullPointerException.class, () -> ProxyJump.through(null));
  }

  private static int closedPort() throws java.io.IOException {
    try (ServerSocket closed = new ServerSocket(0, 1, java.net.InetAddress.getLoopbackAddress())) {
      return closed.getLocalPort();
    }
  }

  @Test
  void sameThreadMayConnectSameAliasWhileAnotherConnectIsInProgress() throws Exception {
    // A callback (here the first hop's SocketFactory) may open an independent session to the
    // same destination on the connecting thread; that is not a cycle.
    int port;
    try (ServerSocket closed = new ServerSocket(0, 1, java.net.InetAddress.getLoopbackAddress())) {
      port = closed.getLocalPort();
    }
    {
      JSch jsch = new JSch();
      jsch.setConfigRepository(
          OpenSSHConfig.parse(String.join("\n", "Host target", "  User u", "  ProxyJump hop",
              "Host hop", "  User u", "  HostName 127.0.0.1", "  Port " + port, "")));
      List<String> nestedErrors = new ArrayList<>();
      SocketFactory factory = new SocketFactory() {
        private boolean nested;

        @Override
        public Socket createSocket(String host, int p) throws java.io.IOException {
          if (!nested) {
            nested = true;
            Session inner = sessionWith(jsch, this);
            try {
              inner.connect(2000);
            } catch (JSchException e) {
              nestedErrors.add(e.getMessage());
            }
          }
          throw new java.io.IOException("refused by test");
        }

        @Override
        public java.io.InputStream getInputStream(Socket socket) {
          return null;
        }

        @Override
        public java.io.OutputStream getOutputStream(Socket socket) {
          return null;
        }
      };
      assertThrows(JSchException.class, () -> sessionWith(jsch, factory).connect(2000));
      assertEquals(1, nestedErrors.size());
      assertFalse(nestedErrors.get(0).contains("cycle"), nestedErrors.get(0));
    }
  }

  private static Session sessionWith(JSch jsch, SocketFactory factory) {
    try {
      Session session = jsch.getSession("target");
      session.setSocketFactory(factory);
      return session;
    } catch (JSchException e) {
      throw new IllegalStateException(e);
    }
  }

  @Test
  void hopUsesOwnHostKeyConfigAndIgnoresTargetSessionSettings() throws Exception {
    Path targetKnownHosts = Files.createFile(tempDir.resolve("target_known_hosts"));
    Path jumpKnownHosts = Files.createFile(tempDir.resolve("jump_known_hosts"));
    JSch jsch = new JSch();
    jsch.setConfigRepository(
        OpenSSHConfig.parse(String.join("\n", "Host target", "  ProxyJump jump",
            "  StrictHostKeyChecking yes", "  UserKnownHostsFile " + targetKnownHosts, "Host jump",
            "  StrictHostKeyChecking no", "  UserKnownHostsFile " + jumpKnownHosts, "")));
    Session target = jsch.getSession("target");
    // Like options given to ssh -J's destination, settings made on the target stay on the target.
    target.setHostKeyRepository(new KnownHosts(jsch));
    target.setConfig("StrictHostKeyChecking", "yes");
    target.setConfig("server_host_key", "ssh-ed25519");
    ProxyJump proxy = new ProxyJump(target, "jump");

    Session hop = proxy.createHop(new ProxyJump.Hop(null, "jump", 0), null, null);
    assertEquals("no", hop.getConfig("StrictHostKeyChecking"));
    assertEquals(jumpKnownHosts.toString(), hop.getHostKeyRepository().getKnownHostsRepositoryID());
    assertEquals(JSch.getConfig("server_host_key"), hop.getConfig("server_host_key"));
  }

  @Test
  void hopSetsUpNoForwardingsUnlessItsConfigAsksForThem() throws Exception {
    JSch jsch = new JSch();
    jsch.setConfigRepository(OpenSSHConfig
        .parse(String.join("\n", "Host forwarding", "  ClearAllForwardings no", "Host clearing",
            "  ClearAllForwardings yes", "Host *", "  LocalForward 8080 localhost:80", "")));
    Session target = jsch.getSession("user", "target");
    ProxyJump proxy = new ProxyJump(target, "plain,forwarding");
    // Like ssh -W behind ssh -J, which clears forwardings unless the jump host's config says no.
    assertEquals("yes", proxy.createHop(new ProxyJump.Hop(null, "plain", 0), null, null)
        .getConfig("ClearAllForwardings"));
    assertEquals("no", proxy.createHop(new ProxyJump.Hop(null, "forwarding", 0), null, null)
        .getConfig("ClearAllForwardings"));
    assertEquals("yes", proxy.createHop(new ProxyJump.Hop(null, "clearing", 0), null, null)
        .getConfig("ClearAllForwardings"));
    assertEquals("no", target.getConfig("ClearAllForwardings"));
  }

  @Test
  void sessionTimeoutReachesTunnel() throws Exception {
    List<Integer> timeouts = new ArrayList<>();
    Session session = new JSch().getSession("u", "target");
    session.setProxy(new ReadTimeoutProxy() {
      @Override
      public void setReadTimeout(int timeout) {
        timeouts.add(timeout);
      }

      @Override
      public void connect(SocketFactory socketFactory, String host, int port, int timeout) {}

      @Override
      public java.io.InputStream getInputStream() {
        return null;
      }

      @Override
      public java.io.OutputStream getOutputStream() {
        return null;
      }

      @Override
      public Socket getSocket() {
        return null;
      }

      @Override
      public void close() {}
    });
    session.setTimeout(1234);
    session.setTimeout(0);
    assertEquals(Arrays.asList(1234, 0), timeouts);
  }

  @Test
  void hopPromptsThroughProxyJumpUserInfoOnlyAndInheritsThreadSettings() throws Exception {
    JSch jsch = new JSch();
    Session target = jsch.getSession("user", "target");
    ThreadFactory factory = Thread::new;
    Logger logger = new JulLogger();
    UserInfo prompts = new UserInfo() {
      @Override
      public String getPassphrase() {
        return null;
      }

      @Override
      public String getPassword() {
        return null;
      }

      @Override
      public boolean promptPassword(String message) {
        return false;
      }

      @Override
      public boolean promptPassphrase(String message) {
        return false;
      }

      @Override
      public boolean promptYesNo(String message) {
        return false;
      }

      @Override
      public void showMessage(String message) {
        // nothing to show
      }
    };
    UserInfo targetOnly = new UserInfo() {
      @Override
      public String getPassphrase() {
        return null;
      }

      @Override
      public String getPassword() {
        return "target-secret";
      }

      @Override
      public boolean promptPassword(String message) {
        return true;
      }

      @Override
      public boolean promptPassphrase(String message) {
        return false;
      }

      @Override
      public boolean promptYesNo(String message) {
        return false;
      }

      @Override
      public void showMessage(String message) {
        // nothing to show
      }
    };
    target.setUserInfo(targetOnly);
    target.setPassword("target-only".getBytes(java.nio.charset.StandardCharsets.UTF_8));
    Session silentHop =
        new ProxyJump(target, "jump").createHop(new ProxyJump.Hop("u", "jump", 0), null, null);
    assertNull(silentHop.getUserInfo(), "the target's UserInfo is never offered to a hop");
    assertNull(silentHop.password, "a password set for the target is not offered to hops");
    target.setProxyJumpUserInfo(prompts);
    target.setDaemonThread(true);
    target.setThreadFactory(factory);
    target.setLogger(logger);
    Session hop =
        new ProxyJump(target, "jump").createHop(new ProxyJump.Hop("u", "jump", 0), null, null);
    assertSame(prompts, hop.getUserInfo(), "hops prompt through the ProxyJump UserInfo");
    assertSame(prompts, hop.getProxyJumpUserInfo(), "and pass it on to hops of their own");
    assertNull(hop.password, "a password set for the target is not offered to hops");
    assertTrue(hop.daemon_thread);
    assertSame(factory, hop.getThreadFactory());
    assertSame(logger, hop.getLogger());
  }

  @Test
  void chainTimeoutIsLargestOnPathNotSum() throws Exception {
    JSch jsch = new JSch();
    jsch.setConfigRepository(OpenSSHConfig.parse(String.join("\n", "Host three",
        "  ConnectTimeout 3", "Host five", "  ConnectTimeout 5", "")));
    List<Session> chain = new ArrayList<>(Arrays.asList(jsch.getSession("u", "three"),
        jsch.getSession("u", "five"), jsch.getSession("u", "none")));
    assertEquals(5000, ProxyJump.connectBudget(0, chain));
    assertEquals(5000, ProxyJump.connectBudget(1000, chain));
    assertEquals(9000, ProxyJump.connectBudget(9000, chain));
    assertEquals(0, ProxyJump.connectBudget(0, chain.subList(2, 3)));
  }

  @Test
  void silentHopHonorsItsConnectTimeoutWhenTargetHasNone() throws Exception {
    List<Socket> accepted = new ArrayList<>();
    try (ServerSocket silent = new ServerSocket(0, 50, java.net.InetAddress.getLoopbackAddress())) {
      Thread acceptor = new Thread(() -> {
        try {
          while (true) {
            accepted.add(silent.accept());
          }
        } catch (java.io.IOException e) {
          if (!silent.isClosed()) {
            throw new IllegalStateException(e);
          }
        }
      });
      acceptor.setDaemon(true);
      acceptor.start();
      JSch jsch = new JSch();
      jsch.setConfigRepository(OpenSSHConfig.parse(String.join("\n", "Host silent",
          "  HostName 127.0.0.1", "  Port " + silent.getLocalPort(), "  User u",
          "  ConnectTimeout 1", "Host target", "  User u", "  ProxyJump silent", "")));
      Session target = jsch.getSession("target");
      long start = System.nanoTime();
      assertTimeoutPreemptively(Duration.ofSeconds(10),
          () -> assertThrows(JSchException.class, () -> target.connect(0)));
      assertTrue(System.nanoTime() - start < java.util.concurrent.TimeUnit.SECONDS.toNanos(5));
    } finally {
      for (Socket socket : accepted) {
        socket.close();
      }
    }
  }

  @Test
  void tunnelHonorsReadTimeoutAndDrainsBeforeEndOfStream() throws Exception {
    ProxyJump.TunnelBuffer tunnel = new ProxyJump.TunnelBuffer(16, 16);
    tunnel.setTimeout(50);
    assertThrows(SocketTimeoutException.class, tunnel::read);
    tunnel.sink().write(42);
    assertEquals(42, tunnel.read());
    tunnel.sink().write(new byte[] {1, 2, 3});
    tunnel.sink().close();
    byte[] buffer = new byte[8];
    assertEquals(3, tunnel.read(buffer, 0, buffer.length));
    assertEquals(-1, tunnel.read());
    assertThrows(java.io.IOException.class, () -> tunnel.sink().write(1));
  }

  @Test
  void tunnelRejectsInvalidRanges() {
    ProxyJump.TunnelBuffer tunnel = new ProxyJump.TunnelBuffer(16, 16);
    byte[] bytes = new byte[4];
    assertThrows(IndexOutOfBoundsException.class, () -> tunnel.sink().write(bytes, 0, -1));
    assertThrows(IndexOutOfBoundsException.class, () -> tunnel.sink().write(bytes, -1, 1));
    assertThrows(IndexOutOfBoundsException.class, () -> tunnel.sink().write(bytes, 2, 3));
    assertThrows(IndexOutOfBoundsException.class, () -> tunnel.read(bytes, 2, 3));
    assertEquals(0, tunnel.available());
  }

  @Test
  void tunnelWrapsGrowsAndNeverStallsWriter() {
    byte[] data = new byte[256 * 1024];
    new java.util.Random(1).nextBytes(data);
    ProxyJump.TunnelBuffer tunnel = new ProxyJump.TunnelBuffer(1024, 4096);
    tunnel.setTimeout(5000);
    Thread producer = new Thread(() -> {
      try {
        for (int i = 0, step = 1; i < data.length; i += step, step = step % 4093 + 1) {
          tunnel.sink().write(data, i, Math.min(step, data.length - i));
        }
        tunnel.sink().close();
      } catch (java.io.IOException e) {
        throw new IllegalStateException(e); // the reader also reports it by timing out
      }
    });
    ByteArrayOutputStream received = new ByteArrayOutputStream();
    assertTimeoutPreemptively(Duration.ofSeconds(10), () -> {
      producer.start();
      byte[] buffer = new byte[8192];
      for (int n; (n = tunnel.read(buffer, 0, buffer.length)) >= 0;) {
        received.write(buffer, 0, n);
      }
    });
    assertArrayEquals(data, received.toByteArray());
  }

  @Test
  void closingTunnelReleasesBlockedWriter() throws Exception {
    ProxyJump.TunnelBuffer tunnel = new ProxyJump.TunnelBuffer(4, 4);
    tunnel.sink().write(new byte[4]);
    List<String> failures = new ArrayList<>();
    Thread writer = new Thread(() -> {
      try {
        tunnel.sink().write(1);
      } catch (java.io.IOException e) {
        failures.add(e.getMessage());
      }
    });
    writer.start();
    assertTimeoutPreemptively(Duration.ofSeconds(10), () -> {
      while (writer.getState() != Thread.State.WAITING) {
        Thread.yield();
      }
      tunnel.close();
      writer.join();
    });
    assertEquals(Arrays.asList("ProxyJump tunnel closed"), failures);
  }
}
