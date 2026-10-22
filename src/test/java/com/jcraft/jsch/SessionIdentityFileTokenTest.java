package com.jcraft.jsch;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Locale;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SessionIdentityFileTokenTest {
  @TempDir
  Path tempDir;

  @Test
  void expandsHomeTokenBeforeLoadingIdentity() throws Exception {
    String originalHome = System.getProperty("user.home");
    try {
      System.setProperty("user.home", tempDir.toString());
      JSch jsch = new JSch();
      Path key = tempDir.resolve("id_test");
      KeyPair.genKeyPair(jsch, KeyPair.RSA, 1024).writePrivateKey(key.toString());
      jsch.setConfigRepository(OpenSSHConfig.parse("Host target\n IdentityFile %d/id_test\n"));

      Session session = jsch.getSession("target");
      assertEquals(key,
          Paths.get(session.getIdentityRepository().getIdentities().get(0).getName()));
      assertEquals(0, jsch.getIdentityRepository().getIdentities().size());
    } finally {
      System.setProperty("user.home", originalHome);
    }
  }

  @Test
  void expandsConnectionTokensAndRejectsUnsupportedOnes() throws Exception {
    JSch jsch = new JSch();
    jsch.setConfigRepository(OpenSSHConfig.parse(
        "Host alias\n HostName real.example\n Port 2222\n User remote\n HostKeyAlias key-alias\n"));
    Session session = jsch.getSession("alias");

    assertEquals(
        "real.example/alias/2222/remote/" + System.getProperty("user.name") + "/key-alias/%",
        ConfigTokenExpander.expandPath("%h/%n/%p/%r/%u/%k/%%", session::resolveConfigToken));
    assertThrows(JSchException.class,
        () -> ConfigTokenExpander.expandPath("%x/key", session::resolveConfigToken));
  }

  @Test
  void expandsHostnameAndKnownHostsPath() throws Exception {
    JSch jsch = new JSch();
    jsch.setConfigRepository(OpenSSHConfig.parse("Host alias\n HostName %h.example\n"
        + " UserKnownHostsFile " + tempDir + "/%n-known_hosts\n"));

    Session session = jsch.getSession("alias");
    assertEquals("alias.example", session.host);
    assertEquals(tempDir.resolve("alias-known_hosts"),
        Paths.get(session.getHostKeyRepository().getKnownHostsRepositoryID()));
  }

  @Test
  void hostKeyAliasTokenDefaultsToOriginalHost() throws Exception {
    JSch jsch = new JSch();
    jsch.setConfigRepository(OpenSSHConfig.parse("Host alias\n HostName real.example\n"
        + " UserKnownHostsFile " + tempDir + "/%k-known_hosts\n"));

    Session session = jsch.getSession("alias");
    assertEquals(tempDir.resolve("alias-known_hosts"),
        Paths.get(session.getHostKeyRepository().getKnownHostsRepositoryID()));
  }

  @Test
  void unsetEnvironmentVariableRejectsTrustStore() throws Exception {
    JSch jsch = new JSch();
    jsch.setConfigRepository(OpenSSHConfig.parse(
        "Host alias\n UserKnownHostsFile ${JSCH_UNSET_KNOWN_HOSTS_TEST_90748}/known_hosts\n"));

    assertThrows(JSchException.class, () -> jsch.getSession("alias"));
  }

  @Test
  void expandsLocalAndConnectionHashTokens() throws Exception {
    JSch jsch = new JSch();
    jsch.setConfigRepository(OpenSSHConfig
        .parse("Host alias\n HostName real.example\n Port 2222\n User remote\n ProxyJump a,b\n"));
    Session session = jsch.getSession("alias");
    String local = java.net.InetAddress.getLocalHost().getHostName();

    assertEquals("a,b", ConfigTokenExpander.expandPath("%j", session::resolveConfigToken));
    assertEquals(local, ConfigTokenExpander.expandPath("%l", session::resolveConfigToken));
    assertEquals(local.split("\\.", 2)[0],
        ConfigTokenExpander.expandPath("%L", session::resolveConfigToken));
    byte[] digest = java.security.MessageDigest.getInstance("SHA-1").digest(
        (local + "real.example2222remotea,b").getBytes(java.nio.charset.StandardCharsets.UTF_8));
    StringBuilder hex = new StringBuilder();
    for (byte b : digest) {
      hex.append(String.format(Locale.ROOT, "%02x", b & 0xff));
    }
    assertEquals(hex.toString(), ConfigTokenExpander.expandPath("%C", session::resolveConfigToken));
    if (java.io.File.separatorChar == '/') {
      assertTrue(ConfigTokenExpander.expandPath("%i", session::resolveConfigToken).matches("\\d+"));
    }

    jsch.setConfigRepository(OpenSSHConfig.parse("Host alias\n HostName real.example\n"));
    assertEquals("",
        ConfigTokenExpander.expandPath("%j", jsch.getSession("alias")::resolveConfigToken));
  }

  @Test
  void expandsTildeBeforeTokens() throws Exception {
    String originalHome = System.getProperty("user.home");
    try {
      Path home = java.nio.file.Files.createDirectory(tempDir.resolve("h%n"));
      System.setProperty("user.home", home.toString());
      JSch jsch = new JSch();
      jsch.setConfigRepository(OpenSSHConfig.parse("Host alias\n"));
      Session session = jsch.getSession("alias");
      assertEquals(home + "/alias",
          ConfigTokenExpander.expandPath("~/%n", session::resolveConfigToken));
      assertEquals(home + "/k", ConfigTokenExpander
          .expandPath("~" + System.getProperty("user.name") + "/k", session::resolveConfigToken));
      assertEquals("~nobody-else/k",
          ConfigTokenExpander.expandPath("~nobody-else/k", session::resolveConfigToken));
    } finally {
      System.setProperty("user.home", originalHome);
    }
  }

  @Test
  void customConfigRepositoryValuesStayLiteral() throws Exception {
    JSch jsch = new JSch();
    Path knownHosts = tempDir.resolve("kh_50%");
    jsch.setConfigRepository(new ConfigRepository() {
      @Override
      public Config getConfig(String host) {
        return new Config() {
          @Override
          public String getHostname() {
            return "a%b";
          }

          @Override
          public String getUser() {
            return "u";
          }

          @Override
          public int getPort() {
            return -1;
          }

          @Override
          public String getValue(String key) {
            return key.equals("UserKnownHostsFile") ? knownHosts.toString() : null;
          }

          @Override
          public String[] getValues(String key) {
            return null;
          }
        };
      }
    });
    Session session = jsch.getSession("alias");
    assertEquals("a%b", session.host);
    assertEquals(knownHosts.toString(), session.getHostKeyRepository().getKnownHostsRepositoryID());
  }

  @Test
  void configIdentitiesKeepOrderAndFollowLaterRepositoryChanges() throws Exception {
    JSch jsch = new JSch();
    Path global = tempDir.resolve("id_global");
    Path specific = tempDir.resolve("id_specific");
    Path added = tempDir.resolve("id_added");
    for (Path key : new Path[] {global, specific, added}) {
      KeyPair.genKeyPair(jsch, KeyPair.RSA, 1024).writePrivateKey(key.toString());
    }
    jsch.addIdentity(added.toString());
    jsch.setConfigRepository(OpenSSHConfig.parse("Host *\n IdentityFile " + global
        + "\nHost target\n IdentityFile " + specific + "\nHost plain\n User u\n"));

    Session session = jsch.getSession("target");
    java.util.List<String> names = new java.util.ArrayList<>();
    for (Identity identity : session.getIdentityRepository().getIdentities()) {
      names.add(identity.getName());
    }
    assertEquals(java.util.Arrays.asList(specific.toString(), added.toString(), global.toString()),
        names);
    assertEquals(1, jsch.getIdentityRepository().getIdentities().size());

    Session plain = jsch.getSession("plain");
    IdentityRepository replacement = new LocalIdentityRepository(jsch.instLogger);
    jsch.setIdentityRepository(replacement);
    assertEquals(1, plain.getIdentityRepository().getIdentities().size()); // only Host * key
    assertEquals(2, session.getIdentityRepository().getIdentities().size());

    jsch.setConfigRepository(OpenSSHConfig.parse("Host bare\n User u\n"));
    Session bare = jsch.getSession("bare");
    assertSame(replacement, bare.getIdentityRepository());
  }

  /** A hash class whose loading fails with an Error rather than an Exception. */
  public static final class ExplodingHash implements HASH {
    static {
      if (Boolean.parseBoolean("true")) {
        throw new IllegalStateException("no hash for you");
      }
    }

    @Override
    public void init() {}

    @Override
    public int getBlockSize() {
      return 0;
    }

    @Override
    public void update(byte[] foo, int start, int len) {}

    @Override
    public byte[] digest() {
      return new byte[0];
    }
  }

  @Test
  void connectionHashFailsClosedWhenTheConfiguredHashIsUnavailable() throws Exception {
    String sha1 = JSch.getConfig("sha-1");
    try {
      for (String hashClass : new String[] {"missing.Sha1", ExplodingHash.class.getName(),
          "com.jcraft.jsch.jce.SHA256"}) {
        JSch.setConfig("sha-1", hashClass);
        JSch jsch = new JSch();
        jsch.setConfigRepository(OpenSSHConfig
            .parse("Host alias\n  UserKnownHostsFile " + tempDir.resolve("%C") + "\n"));
        JSchException error =
            assertThrows(JSchException.class, () -> jsch.getSession("user", "alias", 22));
        assertTrue(error.getMessage().contains("%C"), hashClass + ": " + error.getMessage());
      }
    } finally {
      JSch.setConfig("sha-1", sha1);
    }
  }
}
