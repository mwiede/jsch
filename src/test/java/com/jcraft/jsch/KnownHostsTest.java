package com.jcraft.jsch;

import static java.nio.charset.StandardCharsets.ISO_8859_1;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.LinkedList;
import java.util.Properties;
import java.util.function.Function;
import java.util.stream.Collectors;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import com.jcraft.jsch.KnownHosts.HashedHostKey;
import com.jcraft.jsch.jce.HMACSHA1;
import com.jcraft.jsch.jce.HMACSHA256;
import com.jcraft.jsch.jce.HMACSHA512;

class KnownHostsTest {
  private final static String rsaKey =
      "AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkc"
          + "cKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81e"
          + "FzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpI"
          + "oaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G"
          + "3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ==";
  private final static String hashValue =
      "|1|F1E1KeoE/eEWhi10WpGv4OdiO6Y=|3988QV0VE8wmZL7suNrYQLITLCg=";
  private final static String hostLine = "ssh.example.com,192.168.1.61";
  private final static byte[] dsaKeyBytes = Util.str2byte("    ssh-dsa");
  private final static byte[] rsaKeyBytes = Util.str2byte("    ssh-rsa");
  private LinkedList<String> messages;
  private JSch jsch;
  private Hashtable<String, String> orgConfig;
  private Properties orgProps;

  @BeforeEach
  void setupTest() {
    orgProps = System.getProperties();
    Properties myProps = new Properties(orgProps);
    System.setProperties(myProps);
    orgConfig = new Hashtable<>(JSch.config);
    messages = new LinkedList<>();
    jsch = new JSch();
    jsch.setInstanceLogger(new TestLogger(messages));
  }

  @AfterEach
  void tearDownTest() {
    System.setProperties(orgProps);
    JSch.setConfig(orgConfig);
    Session.random = null;
  }

  @Test
  void testInstantiationValues() throws Exception {
    KnownHosts kh = new KnownHosts(jsch);

    assertNull(kh.getKnownHostsFile(), "check known_hosts filename");
    assertNull(kh.getKnownHostsRepositoryID(), "check repository id");
    assertNotNull(kh.hmacsha1, "hmac instance not expected to be null");
    assertSame(kh.hmacsha1, kh.getHMACSHA1(),
        "same instance should be returned with call of getHMACSHA1");
    assertSame(kh.getHMACSHA1(), kh.getHMACSHA1(),
        "same instance should be returned with call of getHMACSHA1");

    KnownHosts kh2 = new KnownHosts(jsch);
    assertNotNull(kh2.hmacsha1, "hmac instance not expected to be null");
    assertNotSame(kh.hmacsha1, kh2.hmacsha1,
        "hmac instances should be different in different KH-instances");
  }

  @Test
  void testSetKnownHostsByFilename() throws Exception {
    KnownHosts kh = new KnownHosts(jsch) {
      @Override
      void setKnownHosts(InputStream input) throws JSchException {
        messages.add("set known hosts by stream");
        StringBuilder sb = new StringBuilder();
        int read;
        try {
          while ((read = input.read()) != -1) {
            sb.append((char) read);
          }
          messages.add(sb.toString());
        } catch (IOException ioe) {
          throw new JSchException("error while reading hosts file", ioe);
        }
      }
    };

    File hostFile = File.createTempFile("setknownhosts", ".txt");
    try {
      try (FileOutputStream fos = new FileOutputStream(hostFile)) {
        fos.write("some host data".getBytes(ISO_8859_1));
      }
      System.setProperty("user.home", hostFile.getParentFile().getAbsolutePath());
      kh.setKnownHosts("some_filename:that can't exist");
      assertEquals("some_filename:that can't exist", kh.getKnownHostsFile(),
          "check known_hosts filename");
      assertEquals("some_filename:that can't exist", kh.getKnownHostsRepositoryID(),
          "check repository id");

      assertEquals(0, messages.size(), "expected no messages till now");

      kh.setKnownHosts(hostFile.getAbsolutePath());
      assertEquals(hostFile.getAbsolutePath(), kh.getKnownHostsFile(),
          "check known_hosts filename");
      assertEquals(hostFile.getAbsolutePath(), kh.getKnownHostsRepositoryID(),
          "check repository id");
      assertEquals(2, messages.size(), "expected no messages after setting");
      assertEquals("set known hosts by stream", messages.removeFirst(), "check message");
      assertEquals("some host data", messages.removeFirst(), "check message");

      File userDirFile = new File("~", hostFile.getName());
      assertEquals(hostFile.getAbsolutePath(), Util.checkTilde(userDirFile.getPath()),
          "check result of userTilde");
      kh.setKnownHosts(userDirFile.getPath());
      assertEquals(userDirFile.getPath(), kh.getKnownHostsFile(), "check known_hosts filename");
      assertEquals(userDirFile.getPath(), kh.getKnownHostsRepositoryID(), "check repository id");
      assertEquals(2, messages.size(), "expected 2 messages after setting");
      assertEquals("set known hosts by stream", messages.removeFirst(), "check message");
      assertEquals("some host data", messages.removeFirst(), "check message");
    } finally {
      hostFile.delete();
    }
  }

  @Test
  void testCreateAndGetHMACSHA1() throws Exception {
    JSch.setConfig("hmac-sha1", "my.hmac.sha1.class.Name");
    KnownHosts kh = new KnownHosts(jsch) {
      @Override
      MAC createHMAC(String hmacClassname) {
        messages.add("create hmac instance of class " + hmacClassname);
        return null;
      }
    };

    assertNull(kh.hmacsha1, "hmac instance should be null");
    assertEquals("create hmac instance of class my.hmac.sha1.class.Name",
        messages.stream().collect(Collectors.joining("\r\n")));
    messages.clear();

    try {
      new KnownHosts(jsch);
      fail("exception expected");
    } catch (IllegalArgumentException iae) {
      assertEquals("instantiation of my.hmac.sha1.class.Name lead to an error", iae.getMessage(),
          "check exception message");
      Throwable cause = iae.getCause();
      assertNotNull(cause, "cause should not be null");
      assertEquals(ClassNotFoundException.class.getName(), cause.getClass().getName(),
          "unexpected cause");
    }
    assertEquals(
        "M(3): unable to instantiate HMAC-class my.hmac.sha1.class.Name\r\n"
            + "  java.lang.ClassNotFoundException: my.hmac.sha1.class.Name",
        messages.stream().collect(Collectors.joining("\r\n")));
    messages.clear();

    // it's not SHA-1 but for this test any hashing class will do
    JSch.setConfig("hmac-sha1", HMACSHA256.class.getName());
    kh = new KnownHosts(jsch);
    assertNotNull(kh.hmacsha1, "hmac instance should not be null");
    assertSame(kh.hmacsha1, kh.getHMACSHA1(), "instance shouldn't change");
    assertEquals(HMACSHA256.class.getName(), kh.hmacsha1.getClass().getName(),
        "hmac class mismatch");

    MAC currentMAC = kh.hmacsha1;
    JSch.setConfig("hmac-sha1", HMACSHA512.class.getName());
    assertSame(currentMAC, kh.getHMACSHA1(),
        "instance shouldn't change even with now correct config-entry");

    kh = new KnownHosts(jsch);
    assertNotNull(kh.hmacsha1, "hmac instance should not be null");
    assertSame(kh.hmacsha1, kh.getHMACSHA1(), "instance shouldn't change");
    assertEquals(HMACSHA512.class.getName(), kh.hmacsha1.getClass().getName(),
        "hmac class mismatch");
    assertEquals("", messages.stream().collect(Collectors.joining("\r\n")));

  }

  @Test
  void testSetKnownHostsHashedHost() throws Exception {
    KnownHosts kh = new KnownHosts(jsch);
    // comment with umlaut to check used charset for dump
    kh.setKnownHosts(
        new ByteArrayInputStream((hashValue + " " + "ssh-rsa " + rsaKey + " some comment\r\n"
            + "# 192.168.1.61 ssh-rsa MYRSAKEY some other commänt").getBytes(UTF_8)));

    assertEquals(0, messages.size(), "no messages expected");
    HostKey[] keys = kh.getHostKey();
    checkResultForKeyResult(keys, rsaKey, hashValue, "");

    keys = kh.getHostKey("192.168.1.61", "ssh-rsa");
    checkResultForKeyResult(keys, rsaKey, hashValue, "");

    keys = kh.getHostKey("192.168.1.62", "ssh-rsa");
    assertNotNull(keys, "actual keys expected");
    assertEquals(0, keys.length, "0 keys expected");
    keys = kh.getHostKey("192.168.1.61", "ssh-dsa");
    assertNotNull(keys, "actual keys expected");
    assertEquals(0, keys.length, "0 keys expected");

    ByteArrayOutputStream dump = new ByteArrayOutputStream();
    kh.dump(dump);
    assertEquals(
        hashValue + " ssh-rsa " + rsaKey + " some comment\n"
            + "# 192.168.1.61 ssh-rsa MYRSAKEY some other commänt\n" + "",
        dump.toString("UTF8"), "dump mismatch");
  }

  @Test
  void testSetKnownHostsDirectHost() throws Exception {
    KnownHosts kh = new KnownHosts(jsch);
    kh.setKnownHosts(new ByteArrayInputStream(
        ("@cert-authority " + hostLine + " " + "ssh-rsa " + rsaKey + " some comment")
            .getBytes(ISO_8859_1)));

    assertEquals(0, messages.size(), "no messages expected");
    HostKey[] keys = kh.getHostKey();
    checkResultForKeyResult(keys, rsaKey, hostLine, "@cert-authority");

    keys = kh.getHostKey("192.168.1.61", "ssh-rsa");
    checkResultForKeyResult(keys, rsaKey, hostLine, "@cert-authority");
    keys = kh.getHostKey("ssh.example.com", "ssh-rsa");
    checkResultForKeyResult(keys, rsaKey, hostLine, "@cert-authority");

    keys = kh.getHostKey("192.168.1.62", "ssh-rsa");
    assertNotNull(keys, "actual keys expected");
    assertEquals(0, keys.length, "0 keys expected");
    keys = kh.getHostKey("192.168.1.61", "ssh-dsa");
    assertNotNull(keys, "actual keys expected");
    assertEquals(0, keys.length, "0 keys expected");

    ByteArrayOutputStream dump = new ByteArrayOutputStream();
    kh.dump(dump);
    assertEquals("@cert-authority " + hostLine + " ssh-rsa " + rsaKey + " some comment\n" + "",
        dump.toString("8859_1"), "dump mismatch");

    kh.setKnownHosts(new ByteArrayInputStream(
        ("!ssh.example.com,!192.168.1.61 " + "ssh-rsa " + rsaKey + " some comment")
            .getBytes(ISO_8859_1)));
    assertEquals(0, messages.size(), "no messages expected");
    keys = kh.getHostKey();
    checkResultForKeyResult(keys, rsaKey, "!ssh.example.com,!192.168.1.61", "");

    keys = kh.getHostKey("192.168.1.61", "ssh-rsa");
    assertNotNull(keys, "actual keys expected");
    assertEquals(0, keys.length, "0 keys expected");
    keys = kh.getHostKey("ssh.example.com", "ssh-rsa");
    assertNotNull(keys, "actual keys expected");
    assertEquals(0, keys.length, "0 keys expected");

    keys = kh.getHostKey("192.168.1.62", "ssh-rsa");
    assertNotNull(keys, "actual keys expected");
    assertEquals(0, keys.length, "0 keys expected");
    keys = kh.getHostKey("192.168.1.61", "ssh-dsa");
    assertNotNull(keys, "actual keys expected");
    assertEquals(0, keys.length, "0 keys expected");

    dump.reset();
    kh.dump(dump);
    assertEquals("!ssh.example.com,!192.168.1.61" + " ssh-rsa " + rsaKey + " some comment\n" + "",
        dump.toString("8859_1"), "dump mismatch");
  }

  @Test
  void testkSyncDump() throws Exception {
    KnownHosts kh = new KnownHosts(jsch) {
      @Override
      synchronized void sync(String foo) throws IOException {
        messages.add("sync with file '" + foo + "'");
        super.sync(foo);
      }
    };
    File tempFile = File.createTempFile("checksyncdump", ".txt");
    try {
      System.setProperty("user.home", tempFile.getParentFile().getAbsolutePath());
      assertNull(kh.getKnownHostsFile(), "known_hosts expected to be null");
      kh.sync();
      assertEquals(0, messages.size(), "no messages expected");
      kh.setKnownHosts(tempFile.getAbsolutePath());
      assertEquals(0, messages.size(), "no messages expected");
      kh.sync();
      assertEquals("sync with file '" + tempFile.getAbsolutePath() + "'",
          messages.stream().collect(Collectors.joining("\r\n")));
      messages.clear();

      kh = new KnownHosts(jsch) {
        @Override
        void dump(OutputStream out) {
          messages.add("stream based dump called with stream: " + out.getClass().getName());
          try {
            out.write("some dump data".getBytes(ISO_8859_1));
          } catch (IOException ioe) {
            Assertions.fail("exception occurred while trying to write dump to tream", ioe);
          }
        }
      };
      kh.sync(null);
      assertEquals(0, messages.size(), "no messages expected");
      kh.sync(tempFile.getAbsolutePath());
      assertEquals("stream based dump called with stream: java.io.FileOutputStream",
          messages.stream().collect(Collectors.joining("\r\n")));
      messages.clear();
      assertEquals("some dump data", getContent(tempFile.getAbsolutePath()));
      assertTrue(tempFile.delete(), "unable to delete '" + tempFile.getAbsolutePath() + "'");

      String userPath = new File("~", tempFile.getName()).getPath();
      kh.sync(userPath);
      assertEquals("stream based dump called with stream: java.io.FileOutputStream",
          messages.stream().collect(Collectors.joining("\r\n")));
      messages.clear();
      assertEquals("some dump data", getContent(tempFile.getAbsolutePath()));
      assertTrue(tempFile.delete(), "unable to delete '" + tempFile.getAbsolutePath() + "'");

      assertTrue(tempFile.mkdir(), "unable to create '" + tempFile.getAbsolutePath() + "'");
      try {
        kh.sync(tempFile.getAbsolutePath());
        fail("exception expected");
      } catch (FileNotFoundException fnfe) {
        // expected, details are OS-dependent, so no check of message, etc.
      }
      assertEquals(0, messages.size(), "no messages expected");

      kh = new KnownHosts(jsch) {
        @Override
        void dumpHostKey(OutputStream out, HostKey hk) throws IOException {
          if (out == null) {
            throw new NullPointerException("out is null");
          }
          messages.add("dump host key for host " + hk.getHost());
        }
      };

      kh.add(kh.new HashedHostKey("host1.example.com", HostKey.SSHRSA, new byte[1]), null);
      kh.add(kh.new HashedHostKey("host2.example.com", HostKey.SSHRSA, new byte[1]), null);

      kh.dump(null);
      assertEquals(
          "M(3): unable to dump known hosts\r\n" + "  java.lang.NullPointerException: out is null",
          messages.stream().collect(Collectors.joining("\r\n")));
      messages.clear();

      kh.dump(new ByteArrayOutputStream());
      assertEquals(
          "dump host key for host host1.example.com\r\n"
              + "dump host key for host host2.example.com",
          messages.stream().collect(Collectors.joining("\r\n")));
      messages.clear();
    } finally {
      tempFile.delete();
    }
  }

  @Test
  void testDumpHostKey() throws Exception {
    ByteArrayOutputStream sink = new ByteArrayOutputStream();
    KnownHosts kh = new KnownHosts(jsch);

    kh.dumpHostKey(sink,
        new HostKey("", "hostwithoutmarker", HostKey.SSHRSA, "rsakey".getBytes(ISO_8859_1), null));
    assertEquals("hostwithoutmarker ssh-rsa cnNha2V5\n", sink.toString("utf8"), "check dumped key");
    sink.reset();
    kh.dumpHostKey(sink, new HostKey("@somemarker", "hostwithmarker", HostKey.SSHRSA,
        "rsakey".getBytes(ISO_8859_1), null));
    assertEquals("@somemarker hostwithmarker ssh-rsa cnNha2V5\n", sink.toString("utf8"),
        "check dumped key");
    sink.reset();

    kh.dumpHostKey(sink, new HostKey("", "hostwithoutmarker", HostKey.SSHRSA,
        "rsakey".getBytes(ISO_8859_1), "some commänt"));
    assertEquals("hostwithoutmarker ssh-rsa cnNha2V5 some commänt\n", sink.toString("utf8"),
        "check dumped key");
    sink.reset();
    kh.dumpHostKey(sink, new HostKey("@somemarker", "hostwithmarker", HostKey.SSHRSA,
        "rsakey".getBytes(ISO_8859_1), "some commänt"));
    assertEquals("@somemarker hostwithmarker ssh-rsa cnNha2V5 some commänt\n",
        sink.toString("utf8"), "check dumped key");
    sink.reset();

    kh.dumpHostKey(sink, new HostKey("", "hostwithoutmarker", HostKey.UNKNOWN,
        "rsakey".getBytes(ISO_8859_1), "some commänt"));
    assertEquals("hostwithoutmarker\n", sink.toString("utf8"), "check dumped key");
    sink.reset();
  }

  @Test
  void testDeleteSubstring() {
    KnownHosts kh = new KnownHosts(jsch);
    assertEquals("host1,host2", kh.deleteSubString("todelete,host1,host2", "todelete"),
        "check result");
    assertEquals("host1,host2", kh.deleteSubString("host1,todelete,host2", "todelete"),
        "check result");
    assertEquals("host1,host2,todelete",
        kh.deleteSubString("host1,todelete,host2,todelete", "todelete"), "check result");
    assertEquals("host1,host2", kh.deleteSubString("host1,host2,todelete", "todelete"),
        "check result");
    assertEquals("host1,host2,host3", kh.deleteSubString("host1,host2,host3", "todelete"),
        "check result");
    assertEquals("host1,host2,host3,", kh.deleteSubString("host1,host2,host3,", "todelete"),
        "check result");
    assertEquals("", kh.deleteSubString("todelete", "todelete"), "check result");
    assertEquals("nottodelete", kh.deleteSubString("nottodelete", "todelete"), "check result");
  }

  @Test
  void testCreateHashedKey() throws Exception {
    Session.random = new NotSoRandomRandom();
    KnownHosts kh = new KnownHosts(jsch);
    kh.hmacsha1 = null; // this will lead to an NPE if the creation uses this instance

    try {
      kh.createHashedHostKey("host.example.com", "    ssh-rsa".getBytes(ISO_8859_1));
      fail("exception expected");
    } catch (NullPointerException npe) {
      // expected but messages differ between java versions, so we don't check the message
      assertEquals("hash", npe.getStackTrace()[0].getMethodName(), "check hash threw exception");
    }

    kh.hmacsha1 = new HMACSHA256();
    HostKey hostKey =
        kh.createHashedHostKey("host.example.com", "    ssh-rsa".getBytes(ISO_8859_1));
    assertNotNull(hostKey, "returned host key shouldn't be null");
    assertEquals(HashedHostKey.class.getName(), hostKey.getClass().getName(),
        "check type of returned host key");
    HashedHostKey hhk = (HashedHostKey) hostKey;

    assertEquals(
        "|1|AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=|mie6rcAf1aPGk6d+HxnkpvO4HaOAH/Y6YWegs+Xog/s=",
        hhk.getHost(), "host mismatch");
    assertEquals("", hhk.getMarker(), "marker mismatch");
    assertEquals(
        "9c:fb:7f:99:79:01:6d:46:68:87:39:15:4f:f5:cc:9d:71:7a:8b:5a:4a:c1:c7:4b:9c:20:a5:91:c2:6a:ff:5a",
        hhk.getFingerPrint(jsch));
    assertEquals(null, hhk.getComment(), "comment mismatch");
    assertEquals("ICAgIHNzaC1yc2E=", hhk.getKey(), "key mismatch");
    assertEquals("ssh-rsa", hhk.getType(), "type mismatch");
  }

  @Test
  void testHashedKeyCreation() throws Exception {
    Session.random = new NotSoRandomRandom();
    KnownHosts kh = new KnownHosts(jsch);
    HashedHostKey hhk;

    hhk = kh.new HashedHostKey("host.example.com", dsaKeyBytes);
    checkUnhashedHostKey(hhk, "", "host.example.com", "ssh-dss", null);

    hhk.hash();
    checkSHA1HashResult(hhk, "", "ssh-dss", null);

    hhk.hash();
    checkSHA1HashResult(hhk, "", "ssh-dss", null);

    hhk = kh.new HashedHostKey("|1|AAECAwQFBgcICQoLDA0ODxAREhM=|/pE4peaossRYDRp6bEWa348eFLI=",
        dsaKeyBytes);
    checkSHA1HashResult(hhk, "", "ssh-dss", null);

    hhk = kh.new HashedHostKey("|1|AAECAwQFBgcICQoLDA0ODxAREhM=/pE4peaossRYDRp6bEWa348eFLI=",
        dsaKeyBytes);
    checkUnhashedHostKey(hhk, "", "|1|AAECAwQFBgcICQoLDA0ODxAREhM=/pE4peaossRYDRp6bEWa348eFLI=",
        "ssh-dss", null);

    hhk = kh.new HashedHostKey("|1|AAAA|ABCD", dsaKeyBytes);
    checkUnhashedHostKey(hhk, "", "|1|AAAA|ABCD", "ssh-dss", null);

    hhk =
        kh.new HashedHostKey("|1|AAECAwQFBgcICQoLDA0ODxAREhM=|ABCD", HostKey.ED25519, dsaKeyBytes);
    checkUnhashedHostKey(hhk, "", "|1|AAECAwQFBgcICQoLDA0ODxAREhM=|ABCD", "ssh-ed25519", null);

    Mac mac = Mac.getInstance("HMACSHA1", new BouncyCastleProvider());
    kh.hmacsha1 = new BCHMACSHA1(mac);
    hhk = kh.new HashedHostKey("@somemarker", "host.example.com", HostKey.ED448, dsaKeyBytes,
        "some commänt");
    checkUnhashedHostKey(hhk, "@somemarker", "host.example.com", "ssh-ed448", "some commänt");

    hhk.hash();
    checkSHA1HashResult(hhk, "@somemarker", "ssh-ed448", "some commänt");

    hhk.hash(); // should have no effect
    checkSHA1HashResult(hhk, "@somemarker", "ssh-ed448", "some commänt");

    hhk = kh.new HashedHostKey(hhk.getHost(), HostKey.ED448, dsaKeyBytes);
    checkSHA1HashResult(hhk, "", "ssh-ed448", null);
  }

  @Test
  void testHashedHostKeyHashIsMatch() throws Exception {
    String heyKey =
        "0x00:0x01:0x02:0x03:0x04:0x05:0x06:0x07:0x08:0x09:0x0a:0x0b:0x0c:0x0d:0x0e:0x0f:0x10:0x11:0x12:0x13";
    Session.random = new NotSoRandomRandom() {
      @Override
      public void fill(byte[] foo, int start, int len) {
        messages.add("fill in random called");
        super.fill(foo, start, len);
      }
    };
    KnownHosts kh = new KnownHosts(jsch);
    boolean[] throwException = new boolean[1];
    Mac mac = Mac.getInstance("HMACSHA1", new BouncyCastleProvider());
    kh.hmacsha1 = new BCHMACSHA1(mac) {
      @Override
      public void init(byte[] key) throws Exception {
        messages.add("init in mac called with key " + Util.toHex(key));
        if (throwException[0]) {
          throw new IOException("dummy ioe");
        }
        super.init(key);
      }
    };
    HashedHostKey hhk = kh.new HashedHostKey("@somemarker", "host.example.com", HostKey.ED448,
        dsaKeyBytes, "some commänt");
    checkUnhashedHostKey(hhk, "@somemarker", "host.example.com", "ssh-ed448", "some commänt");
    assertEquals(0, messages.size(), "expected no messages");
    assertTrue(hhk.isMatched("host.example.com"), "match expected");
    assertFalse(hhk.isMatched("otherhost.example.com"), "no match expected");

    hhk.hash();
    checkSHA1HashResult(hhk, "@somemarker", "ssh-ed448", "some commänt");
    assertEquals("fill in random called\r\n" + "init in mac called with key " + heyKey,
        messages.stream().collect(Collectors.joining("\r\n")));
    messages.clear();
    assertTrue(hhk.isMatched("host.example.com"), "match expected");
    assertEquals("init in mac called with key " + heyKey,
        messages.stream().collect(Collectors.joining("\r\n")));
    messages.clear();
    assertFalse(hhk.isMatched("otherhost.example.com"), "no match expected");
    assertEquals("init in mac called with key " + heyKey,
        messages.stream().collect(Collectors.joining("\r\n")));
    messages.clear();

    hhk.hash();
    assertEquals(0, messages.size(), "expected no messages");

    hhk = kh.new HashedHostKey("@somemarker", "host.example.com", HostKey.ED448, dsaKeyBytes,
        "some commänt");
    hhk.salt = new byte[mac.getMacLength()];
    Session.random.fill(hhk.salt, 0, hhk.salt.length);
    messages.clear();
    hhk.hash();
    checkSHA1HashResult(hhk, "@somemarker", "ssh-ed448", "some commänt");
    assertEquals("init in mac called with key " + heyKey,
        messages.stream().collect(Collectors.joining("\r\n")));
    messages.clear();

    hhk = kh.new HashedHostKey("@somemarker", "host.example.com", HostKey.ED448, dsaKeyBytes,
        "some commänt");
    throwException[0] = true;
    checkUnhashedHostKey(hhk, "@somemarker", "host.example.com", "ssh-ed448", "some commänt");
    hhk.hash();
    checkUnhashedHostKey(hhk, "@somemarker", "host.example.com", "ssh-ed448", "some commänt");
    assertEquals("fill in random called\r\n" + "init in mac called with key " + heyKey + "\r\n"
        + "M(3): an error occurred while trying to calculate the hash for host host.example.com\r\n"
        + "  java.io.IOException: dummy ioe",
        messages.stream().collect(Collectors.joining("\r\n")));
    messages.clear();

    throwException[0] = false;
    hhk.hash();
    checkSHA1HashResult(hhk, "@somemarker", "ssh-ed448", "some commänt");
    messages.clear();
    throwException[0] = true;
    assertFalse(hhk.isMatched("host.example.com"), "no match expected");
    assertEquals(
        "init in mac called with key " + heyKey + "\r\n"
            + "M(3): an error occurred while trying to check hash for host host.example.com\r\n"
            + "  java.io.IOException: dummy ioe",
        messages.stream().collect(Collectors.joining("\r\n")));
    messages.clear();
  }

  @Test
  void testSyncKnownHostsFile() throws Exception {
    boolean[] throwException = new boolean[1];
    KnownHosts kh = new KnownHosts(jsch) {
      @Override
      void sync() throws IOException {
        messages.add("sync() called");
        throw new IOException("shouldn't be called");
      }

      @Override
      synchronized void sync(String filename) throws IOException {
        messages.add("sync called with file " + filename);
        if (throwException[0]) {
          throw new RuntimeException("dummy re");
        }
      }
    };
    LinkedList<Function<String, Boolean>> promptHandlers = new LinkedList<>();
    UserInfo checkUI = new UserInfo() {
      @Override
      public void showMessage(String message) {
        messages.add("UIM: " + message);
      }

      @Override
      public boolean promptYesNo(String message) {
        messages.add("UIPYN: " + message);
        if (promptHandlers.isEmpty()) {
          return false;
        }
        Function<String, Boolean> function = promptHandlers.removeFirst();
        return function.apply(message).booleanValue();
      }

      @Override
      public boolean promptPassword(String message) {
        throw new RuntimeException("promptPassword shouldn't be called");
      }

      @Override
      public boolean promptPassphrase(String message) {
        throw new RuntimeException("promptPassphrase shouldn't be called");
      }

      @Override
      public String getPassword() {
        throw new RuntimeException("getPassword shouldn't be called");
      }

      @Override
      public String getPassphrase() {
        throw new RuntimeException("getPassphrase shouldn't be called");
      }
    };

    File tempFile = File.createTempFile("syncknownhostfile", ".dir");
    assertTrue(tempFile.delete(), "unable to delete " + tempFile.getAbsolutePath());
    File subDirFile = new File(tempFile, "subdir/known_hosts");
    String subdirParentAbsPath = subDirFile.getParentFile().getAbsolutePath();

    try {
      assertNull(kh.getKnownHostsRepositoryID(), "repository id should be null");
      kh.syncKnownHostsFile(null);
      assertEquals(0, messages.size(), "no messages expected");

      kh.setKnownHosts(tempFile.getAbsolutePath());
      assertEquals(tempFile.getAbsolutePath(), kh.getKnownHostsRepositoryID(),
          "repository id should be the temp file's absolute path");
      kh.syncKnownHostsFile(null);
      assertEquals(0, messages.size(), "no messages expected");

      promptHandlers.add((message) -> checkMessageAndReturn(
          tempFile.getAbsolutePath() + " does not exist.\n" + "Are you sure you want to create it?",
          message, false));
      kh.syncKnownHostsFile(checkUI);
      assertEquals(
          "UIPYN: " + tempFile.getAbsolutePath() + " does not exist.\n"
              + "Are you sure you want to create it?",
          messages.stream().collect(Collectors.joining("\r\n")));
      messages.clear();
      assertFalse(tempFile.exists(), "file shouldn't exist after call");

      kh.setKnownHosts(subDirFile.getAbsolutePath());
      promptHandlers.add((message) -> checkMessageAndReturn(subDirFile.getAbsolutePath()
          + " does not exist.\n" + "Are you sure you want to create it?", message, true));
      promptHandlers
          .add((message) -> checkMessageAndReturn("The parent directory " + subdirParentAbsPath
              + " does not exist.\n" + "Are you sure you want to create it?", message, false));
      kh.syncKnownHostsFile(checkUI);
      assertEquals(
          "UIPYN: " + subDirFile.getAbsolutePath() + " does not exist.\n"
              + "Are you sure you want to create it?\r\n" + "UIPYN: The parent directory "
              + subdirParentAbsPath + " does not exist.\n" + "Are you sure you want to create it?",
          messages.stream().collect(Collectors.joining("\r\n")));
      messages.clear();
      assertFalse(subDirFile.exists(), "file shouldn't exist after call");
      assertFalse(tempFile.exists(), "subdir shouldn't exist after call");

      assertTrue(tempFile.createNewFile(), "unable to create " + tempFile.getAbsolutePath());
      promptHandlers.add((message) -> checkMessageAndReturn(subDirFile.getAbsolutePath()
          + " does not exist.\n" + "Are you sure you want to create it?", message, true));
      promptHandlers
          .add((message) -> checkMessageAndReturn("The parent directory " + subdirParentAbsPath
              + " does not exist.\n" + "Are you sure you want to create it?", message, true));
      kh.syncKnownHostsFile(checkUI);
      assertEquals("UIPYN: " + subDirFile.getAbsolutePath() + " does not exist.\n"
          + "Are you sure you want to create it?\r\n" + "UIPYN: The parent directory "
          + subdirParentAbsPath + " does not exist.\n" + "Are you sure you want to create it?\r\n"
          + "UIM: " + subdirParentAbsPath + " has not been created.",
          messages.stream().collect(Collectors.joining("\r\n")));
      messages.clear();
      assertFalse(subDirFile.exists(), "file shouldn't exist after call");
      assertTrue(tempFile.isFile(), "subdir should exist as file after call");

      assertTrue(tempFile.delete(), "unable to delete " + tempFile.getAbsolutePath());
      promptHandlers.add((message) -> checkMessageAndReturn(subDirFile.getAbsolutePath()
          + " does not exist.\n" + "Are you sure you want to create it?", message, true));
      promptHandlers
          .add((message) -> checkMessageAndReturn("The parent directory " + subdirParentAbsPath
              + " does not exist.\n" + "Are you sure you want to create it?", message, true));
      kh.syncKnownHostsFile(checkUI);
      assertEquals(
          "UIPYN: " + subDirFile.getAbsolutePath() + " does not exist.\n"
              + "Are you sure you want to create it?\r\n" + "UIPYN: The parent directory "
              + subdirParentAbsPath + " does not exist.\n"
              + "Are you sure you want to create it?\r\n" + "UIM: " + subdirParentAbsPath
              + " has been succesfully created.\n" + "Please check its access permission.\r\n"
              + "sync called with file " + subDirFile.getAbsolutePath(),
          messages.stream().collect(Collectors.joining("\r\n")));
      messages.clear();
      assertFalse(subDirFile.exists(), "file shouldn't exist after call");
      assertTrue(tempFile.isDirectory(), "subdir should exist as directory after call");

      assertTrue(subDirFile.createNewFile(), "unable to create " + subDirFile.getAbsolutePath());
      kh.syncKnownHostsFile(checkUI);
      assertEquals("sync called with file " + subDirFile.getAbsolutePath(),
          messages.stream().collect(Collectors.joining("\r\n")));
      messages.clear();
      assertTrue(subDirFile.exists(), "file should exist (we've created it)");
      assertTrue(tempFile.isDirectory(), "subdir should exist as directory after call");

      throwException[0] = true;
      kh.syncKnownHostsFile(checkUI);
      assertEquals(
          "sync called with file " + subDirFile.getAbsolutePath() + "\r\n"
              + "M(3): unable to sync known host file " + subDirFile.getAbsolutePath() + "\r\n"
              + "  java.lang.RuntimeException: dummy re",
          messages.stream().collect(Collectors.joining("\r\n")));
      messages.clear();
    } finally {
      if (tempFile != null) {
        subDirFile.delete();
        subDirFile.getParentFile().delete();
        tempFile.delete();
      }
    }
  }

  @Test
  public void testCheck() throws Exception {
    KnownHosts kh = new KnownHosts(jsch);
    String expectedExceptionMessage = "";
    try {
      new HostKey("host.example.com", HostKey.GUESS, new byte[0]);
      fail("exception expected");
    } catch (Exception e) {
      expectedExceptionMessage = e.getMessage();
    }

    assertEquals(KnownHosts.NOT_INCLUDED, kh.check(null, new byte[0]),
        "null host should return NOT_INCLUDED");
    assertEquals(0, messages.size(),
        "no messages expected: " + messages.stream().collect(Collectors.joining("\r\n")));
    assertEquals(KnownHosts.NOT_INCLUDED, kh.check("host.example.com", new byte[0]),
        "empty key should return NOT_INCLUDED");
    assertEquals(1, messages.size(),
        "only one message: " + messages.stream().collect(Collectors.joining("\r\n")));
    assertEquals(
        "M(0): exception while trying to read key while checking host 'host.example.com'\r\n"
            + "  java.lang.ArrayIndexOutOfBoundsException: " + expectedExceptionMessage,
        messages.removeFirst(), "unexpected message");

    addHosts(kh);
    assertEquals(KnownHosts.NOT_INCLUDED, kh.check("host.example.com", dsaKeyBytes),
        "type mismatch should return NOT_INCLUDED");
    assertEquals(KnownHosts.OK, kh.check("host.example.com", rsaKeyBytes),
        "fitting key should return OK");
    assertEquals(KnownHosts.OK, kh.check("192.277.325.3", rsaKeyBytes),
        "fitting key should return OK");
    assertEquals(KnownHosts.OK, kh.check("192.277.325.5", dsaKeyBytes),
        "fitting key should return OK");
    assertEquals(KnownHosts.OK, kh.check("[192.277.325.5]:123", dsaKeyBytes),
        "fitting key should return OK");
    assertEquals(KnownHosts.NOT_INCLUDED, kh.check("[192.277.325.5:123]", dsaKeyBytes),
        "invalid syntax should return NOT_INCLUDED");
    assertEquals(KnownHosts.NOT_INCLUDED, kh.check("[]:123", dsaKeyBytes),
        "invalid syntax should return NOT_INCLUDED");

    assertEquals(KnownHosts.CHANGED,
        kh.check("host.example.com", "    ssh-rsa1234".getBytes(ISO_8859_1)),
        "changed key should return CHANGED");
    assertEquals(KnownHosts.NOT_INCLUDED, kh.check("host2.example.com", rsaKeyBytes),
        "host mismatch should return NOT_INCLUDED");

    assertEquals(KnownHosts.NOT_INCLUDED, kh.check("192.277.325.5", rsaKeyBytes),
        "wrong key should return NOT_INCLUDED");
    assertEquals(KnownHosts.OK, kh.check("[192.277.325.5]:123", dsaKeyBytes),
        "fitting key should return OK");
    assertEquals(KnownHosts.OK, kh.check("[192.277.325.5]:123", rsaKeyBytes),
        "fitting key should return OK");

    assertEquals(0, messages.size(), "no messages expected: " + getMessagesAsString());
  }

  @Test
  public void testAddGetRemoveHostKeys() throws Exception {
    boolean[] throwException = new boolean[1];
    Session.random = new NotSoRandomRandom();
    KnownHosts kh = new KnownHosts(jsch) {
      @Override
      void sync() throws IOException {
        messages.add("sync");
        if (throwException[0]) {
          messages.add("throw exception");
          throw new RuntimeException("dummy re");
        }
      }
    };
    HostKey[] hosts;

    addHosts(kh);

    hosts = kh.getHostKey();
    assertEquals(3, hosts.length, "unexpected number of host keys");
    assertEquals(
        "host.example.com,192.277.325.3: key type ssh-rsa\r\n"
            + "192.277.325.5: key type ssh-dss\r\n" + "[192.277.325.5]:123: key type ssh-rsa",
        getHostKeysString(hosts), "unexpected hosts");

    hosts = kh.getHostKey("nohost.example.com", null);
    assertEquals(0, hosts.length, "unexpected number of host keys");

    hosts = kh.getHostKey("host.example.com", null);
    assertEquals(1, hosts.length, "unexpected number of host keys");
    assertEquals("host.example.com,192.277.325.3: key type ssh-rsa", getHostKeysString(hosts),
        "unexpected hosts");

    hosts = kh.getHostKey("192.277.325.5", null);
    assertEquals(1, hosts.length, "unexpected number of host keys");
    assertEquals("192.277.325.5: key type ssh-dss", getHostKeysString(hosts), "unexpected hosts");

    hosts = kh.getHostKey("[192.277.325.5]:123", null);
    assertEquals(2, hosts.length, "unexpected number of host keys");
    assertEquals("[192.277.325.5]:123: key type ssh-rsa\r\n" + "192.277.325.5: key type ssh-dss",
        getHostKeysString(hosts), "unexpected hosts");

    hosts = kh.getHostKey("[192.277.325.5]:123", "ssh-dss");
    assertEquals(1, hosts.length, "unexpected number of host keys");
    assertEquals("192.277.325.5: key type ssh-dss", getHostKeysString(hosts), "unexpected hosts");

    hosts = kh.getHostKey("[192.277.325.5:123]", "ssh-dss");
    assertEquals(0, hosts.length, "unexpected number of host keys");

    assertEquals(0, messages.size(), "unexpected number of messages: " + getMessagesAsString());

    kh.remove(null, null);
    hosts = kh.getHostKey();
    assertEquals(0, hosts.length, "unexpected number of host keys: " + getHostKeysString(hosts));
    assertEquals("sync", getMessagesAsString(), "unexpected messages");

    addHosts(kh);
    kh.remove(null, "ssh-dsa");
    hosts = kh.getHostKey();
    assertEquals(0, hosts.length, "unexpected number of host keys: " + getHostKeysString(hosts));
    assertEquals("sync", getMessagesAsString(), "unexpected messages");

    addHosts(kh);
    kh.remove("host.example.com", null);
    hosts = kh.getHostKey();
    assertEquals(3, hosts.length, "unexpected number of host keys: " + getHostKeysString(hosts));
    assertEquals(
        "192.277.325.3: key type ssh-rsa\r\n" + "192.277.325.5: key type ssh-dss\r\n"
            + "[192.277.325.5]:123: key type ssh-rsa",
        getHostKeysString(hosts), "unexpected hosts");
    assertEquals("sync", getMessagesAsString(), "unexpected messages");

    kh.remove("[192.277.325.5]:123", "ssh-dsa");
    hosts = kh.getHostKey();
    assertEquals(3, hosts.length, "unexpected number of host keys: " + getHostKeysString(hosts));
    assertEquals(
        "192.277.325.3: key type ssh-rsa\r\n" + "192.277.325.5: key type ssh-dss\r\n"
            + "[192.277.325.5]:123: key type ssh-rsa",
        getHostKeysString(hosts), "unexpected hosts");
    assertEquals("", getMessagesAsString(), "unexpected messages");

    kh.remove("[192.277.325.5]:123", "ssh-rsa", "    ssh-rsa1234".getBytes(ISO_8859_1));
    hosts = kh.getHostKey();
    assertEquals(3, hosts.length, "unexpected number of host keys: " + getHostKeysString(hosts));
    assertEquals(
        "192.277.325.3: key type ssh-rsa\r\n" + "192.277.325.5: key type ssh-dss\r\n"
            + "[192.277.325.5]:123: key type ssh-rsa",
        getHostKeysString(hosts), "unexpected hosts");
    assertEquals("", getMessagesAsString(), "unexpected messages");

    kh.remove("[192.277.325.5]:123", "ssh-rsa", rsaKeyBytes);
    hosts = kh.getHostKey();
    assertEquals(2, hosts.length, "unexpected number of host keys: " + getHostKeysString(hosts));
    assertEquals("192.277.325.3: key type ssh-rsa\r\n" + "192.277.325.5: key type ssh-dss",
        getHostKeysString(hosts), "unexpected hosts");
    assertEquals("sync", getMessagesAsString(), "unexpected messages");

    HashedHostKey hhk = kh.new HashedHostKey("hashed.example.com", rsaKeyBytes);
    kh.add(hhk, null);
    hosts = kh.getHostKey();
    assertEquals(3, hosts.length, "unexpected number of host keys: " + getHostKeysString(hosts));
    assertEquals("192.277.325.3: key type ssh-rsa\r\n" + "192.277.325.5: key type ssh-dss\r\n"
        + "hashed.example.com: key type ssh-rsa", getHostKeysString(hosts), "unexpected hosts");
    assertEquals("", getMessagesAsString(), "unexpected messages");

    kh.remove("nothashed.example.com", "ssh-rsa");
    hosts = kh.getHostKey();
    assertEquals(3, hosts.length, "unexpected number of host keys: " + getHostKeysString(hosts));
    assertEquals("192.277.325.3: key type ssh-rsa\r\n" + "192.277.325.5: key type ssh-dss\r\n"
        + "hashed.example.com: key type ssh-rsa", getHostKeysString(hosts), "unexpected hosts");
    assertEquals("", getMessagesAsString(), "unexpected messages");

    kh.remove("hashed.example.com", "ssh-rsa");
    hosts = kh.getHostKey();
    assertEquals(2, hosts.length, "unexpected number of host keys: " + getHostKeysString(hosts));
    assertEquals("192.277.325.3: key type ssh-rsa\r\n" + "192.277.325.5: key type ssh-dss",
        getHostKeysString(hosts), "unexpected hosts");
    assertEquals("sync", getMessagesAsString(), "unexpected messages");

    hhk.hash();
    kh.add(hhk, null);
    hosts = kh.getHostKey();
    assertEquals(3, hosts.length, "unexpected number of host keys: " + getHostKeysString(hosts));
    assertEquals(
        "192.277.325.3: key type ssh-rsa\r\n" + "192.277.325.5: key type ssh-dss\r\n"
            + "|1|AAECAwQFBgcICQoLDA0ODxAREhM=|tfTk2zfUwEOJq8/nQE8s/gLfc58=: key type ssh-rsa",
        getHostKeysString(hosts), "unexpected hosts");
    assertEquals("", getMessagesAsString(), "unexpected messages");

    kh.remove("nothashed.example.com", "ssh-rsa");
    hosts = kh.getHostKey();
    assertEquals(3, hosts.length, "unexpected number of host keys: " + getHostKeysString(hosts));
    assertEquals(
        "192.277.325.3: key type ssh-rsa\r\n" + "192.277.325.5: key type ssh-dss\r\n"
            + "|1|AAECAwQFBgcICQoLDA0ODxAREhM=|tfTk2zfUwEOJq8/nQE8s/gLfc58=: key type ssh-rsa",
        getHostKeysString(hosts), "unexpected hosts");
    assertEquals("", getMessagesAsString(), "unexpected messages");

    kh.remove("hashed.example.com", "ssh-rsa");
    hosts = kh.getHostKey();
    assertEquals(2, hosts.length, "unexpected number of host keys: " + getHostKeysString(hosts));
    assertEquals("192.277.325.3: key type ssh-rsa\r\n" + "192.277.325.5: key type ssh-dss",
        getHostKeysString(hosts), "unexpected hosts");
    assertEquals("sync", getMessagesAsString(), "unexpected messages");

    throwException[0] = true;
    kh.remove("192.277.325.5", "ssh-dss");
    hosts = kh.getHostKey();
    assertEquals(1, hosts.length, "unexpected number of host keys: " + getHostKeysString(hosts));
    assertEquals("192.277.325.3: key type ssh-rsa", getHostKeysString(hosts), "unexpected hosts");
    assertEquals("sync\r\n" + "throw exception", getMessagesAsString(), "unexpected messages");

    kh.remove(null, null);
    addHosts(kh);
    hosts = kh.getHostKey();
    assertEquals(3, hosts.length, "unexpected number of host keys: " + getHostKeysString(hosts));
    assertEquals(
        "host.example.com,192.277.325.3: key type ssh-rsa\r\n"
            + "192.277.325.5: key type ssh-dss\r\n" + "[192.277.325.5]:123: key type ssh-rsa",
        getHostKeysString(hosts), "unexpected hosts");
    assertEquals("sync\r\n" + "throw exception", getMessagesAsString(), "unexpected messages");

    kh.remove("192.277.325.5", null);
    hosts = kh.getHostKey("[192.277.325.5]:123", null);
    assertEquals(1, hosts.length, "unexpected number of host keys: " + getHostKeysString(hosts));
    assertEquals("[192.277.325.5]:123: key type ssh-rsa", getHostKeysString(hosts),
        "unexpected hosts");

  }

  private String getMessagesAsString() {
    try {
      return messages.stream().collect(Collectors.joining("\r\n"));
    } finally {
      messages.clear();
    }
  }

  private void addHosts(KnownHosts kh) throws JSchException {
    kh.add(new HostKey("host.example.com,192.277.325.3", rsaKeyBytes), null);
    kh.add(new HostKey("192.277.325.5", dsaKeyBytes), null);
    kh.add(new HostKey("[192.277.325.5]:123", rsaKeyBytes), null);
  }

  private String getHostKeysString(HostKey[] hosts) {
    return Arrays.stream(hosts).map(host -> host.getHost() + ": key type " + host.getType())
        .collect(Collectors.joining("\r\n"));
  }

  private Boolean checkMessageAndReturn(String expectedMessge, String actual, boolean ret) {
    assertEquals(expectedMessge, actual, "prompted message mismatch");
    return Boolean.valueOf(ret);
  }

  private void checkUnhashedHostKey(HashedHostKey hhk, String expectedMarker, String expctedHost,
      String expectedType, String expectedComment) {
    assertEquals(expctedHost, hhk.getHost(), "host mismatch");
    assertEquals(expectedMarker, hhk.getMarker(), "marker mismatch");
    assertEquals(
        "1e:b5:70:92:65:6e:6a:f9:d6:7a:a9:43:00:40:a2:e7:c8:51:35:df:ee:60:19:b7:4b:18:1d:eb:46:48:28:4b",
        hhk.getFingerPrint(jsch));
    assertEquals(expectedComment, hhk.getComment(), "comment mismatch");
    assertEquals("ICAgIHNzaC1kc2E=", hhk.getKey(), "key mismatch");
    assertEquals(expectedType, hhk.getType(), "type mismatch");
    assertFalse(hhk.isHashed(), "key should report itself unhashed");
    assertNull(hhk.salt, "salt should be null");
    assertNull(hhk.hash, "hash should be null");
  }

  private void checkSHA1HashResult(HashedHostKey hhk, String expectedMarker, String expectedType,
      String expectedComment) throws UnsupportedEncodingException {
    assertEquals("|1|AAECAwQFBgcICQoLDA0ODxAREhM=|/pE4peaossRYDRp6bEWa348eFLI=", hhk.getHost(),
        "host mismatch");
    assertEquals(expectedMarker, hhk.getMarker(), "marker mismatch");
    assertEquals(
        "1e:b5:70:92:65:6e:6a:f9:d6:7a:a9:43:00:40:a2:e7:c8:51:35:df:ee:60:19:b7:4b:18:1d:eb:46:48:28:4b",
        hhk.getFingerPrint(jsch));
    assertEquals(expectedComment, hhk.getComment(), "comment mismatch");
    assertEquals("ICAgIHNzaC1kc2E=", hhk.getKey(), "key mismatch");
    assertEquals(expectedType, hhk.getType(), "type mismatch");
    assertTrue(hhk.isHashed(), "key should report itself hashed");
    assertEquals("AAECAwQFBgcICQoLDA0ODxAREhM=",
        new String(Util.toBase64(hhk.salt, 0, hhk.salt.length, true), ISO_8859_1),
        "salt should be null");
    assertEquals("/pE4peaossRYDRp6bEWa348eFLI=",
        new String(Util.toBase64(hhk.hash, 0, hhk.hash.length, true), ISO_8859_1),
        "salt should be null");
  }

  private String getContent(String filename) throws IOException {
    try (FileInputStream fis = new FileInputStream(filename)) {
      StringBuilder sb = new StringBuilder();
      int read;
      while ((read = fis.read()) != -1) {
        sb.append((char) read);
      }
      return sb.toString();
    }
  }

  private void checkResultForKeyResult(HostKey[] keys, String rsaKey, String expectedHostResult,
      String expectedMarker) {
    assertNotNull(keys, "actual keys expected");
    assertEquals(1, keys.length, "1 key expected");
    HostKey key = keys[0];
    assertEquals("some comment", key.getComment(), "comment mismatch");
    assertEquals(
        "9d:38:5b:83:a9:17:52:92:56:1a:5e:c4:d4:81:8e:0a:ca:51:a2:64:f1:74:20:11:2e:f8:8a:c3:a1:39:49:8f",
        key.getFingerPrint(jsch), "fingerprint mismatch");
    assertEquals(expectedHostResult, key.getHost(), "host mismatch");
    assertEquals(rsaKey, key.getKey(), "key mismatch");
    assertEquals(expectedMarker, key.getMarker(), "marker mismatch");
    assertEquals("ssh-rsa", key.getType(), "type mismatch");
  }

  private static class BCHMACSHA1 implements MAC {
    private final Mac mac;

    private BCHMACSHA1(Mac mac) {
      this.mac = mac;
    }

    @Override
    public void update(int foo) {
      mac.update((byte) foo);
    }

    @Override
    public void update(byte[] foo, int start, int len) {
      mac.update(foo, start, len);
    }

    @Override
    public void init(byte[] key) throws Exception {
      SecretKey k = new SecretKeySpec(key, "hmacsha1");
      mac.init(k);
    }

    @Override
    public String getName() {
      return mac.getAlgorithm();
    }

    @Override
    public int getBlockSize() {
      return mac.getMacLength();
    }

    @Override
    public void doFinal(byte[] buf, int offset) {
      try {
        mac.doFinal(buf, offset);
      } catch (ShortBufferException sbe) {
        throw new RuntimeException("unable to do final", sbe);
      }
    }
  }

  private static class NotSoRandomRandom extends com.jcraft.jsch.jce.Random {
    @Override
    public void fill(byte[] foo, int start, int len) {
      for (int i = 0; i < len; i++) {
        foo[i + start] = (byte) i;
      }
    }
  }

  private static class TestLogger implements Logger {
    private final LinkedList<String> messages;

    private TestLogger(LinkedList<String> messages) {
      this.messages = messages;
    }

    @Override
    public void log(int level, String message) {
      messages.add("M(" + level + "): " + message);
    }

    @Override
    public void log(int level, String message, Throwable cause) {
      if (cause != null) {
        message += "\r\n  " + cause.getClass().getName() + ": " + cause.getMessage();
      }
      messages.add("M(" + level + "): " + message);
    }

    @Override
    public boolean isEnabled(int level) {
      return true;
    }
  }

}
