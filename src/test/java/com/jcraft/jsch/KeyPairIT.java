package com.jcraft.jsch;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.condition.JRE.JAVA_15;

import java.net.URISyntaxException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.condition.EnabledForJreRange;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.testcontainers.containers.Container.ExecResult;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.MountableFile;

@Testcontainers
public class KeyPairIT {

  static String keypairgen_eddsa;
  static String ssh_ed25519;

  @TempDir
  public Path tmpDir;

  @BeforeAll
  public static void beforeAll() {
    keypairgen_eddsa = JSch.getConfig("keypairgen.eddsa");
    ssh_ed25519 = JSch.getConfig("ssh-ed25519");
  }

  @AfterEach
  public void afterEach() {
    JSch.setConfig("keypairgen.eddsa", keypairgen_eddsa);
    JSch.setConfig("ssh-ed25519", ssh_ed25519);
  }

  @Container
  public GenericContainer<?> sshd = new GenericContainer<>(
      new ImageFromDockerfile().withFileFromClasspath("sshd_config", "docker/sshd_config")
          .withFileFromClasspath("authorized_keys", "docker/authorized_keys.KeyPairIT")
          .withFileFromClasspath("Dockerfile", "docker/Dockerfile.KeyPairIT"))
      .withExposedPorts(22);

  static Stream<Arguments> writeOpenSSHv1KeyArgs() {
    return Stream.of(Arguments.of(KeyPair.DSA, 1024, null, null),
        Arguments.of(KeyPair.DSA, 1024, "secret123".getBytes(UTF_8), null),
        Arguments.of(KeyPair.DSA, 1024, "secret123".getBytes(UTF_8), "aes256-gcm@openssh.com"),
        Arguments.of(KeyPair.DSA, 1024, "secret123".getBytes(UTF_8),
            "chacha20-poly1305@openssh.com"),
        Arguments.of(KeyPair.RSA, 3072, null, null),
        Arguments.of(KeyPair.RSA, 3072, "secret123".getBytes(UTF_8), null),
        Arguments.of(KeyPair.RSA, 3072, "secret123".getBytes(UTF_8), "aes256-gcm@openssh.com"),
        Arguments.of(KeyPair.RSA, 3072, "secret123".getBytes(UTF_8),
            "chacha20-poly1305@openssh.com"),
        Arguments.of(KeyPair.ECDSA, 256, null, null),
        Arguments.of(KeyPair.ECDSA, 256, "secret123".getBytes(UTF_8), null),
        Arguments.of(KeyPair.ECDSA, 256, "secret123".getBytes(UTF_8), "aes256-gcm@openssh.com"),
        Arguments.of(KeyPair.ECDSA, 256, "secret123".getBytes(UTF_8),
            "chacha20-poly1305@openssh.com"),
        Arguments.of(KeyPair.ECDSA, 384, null, null),
        Arguments.of(KeyPair.ECDSA, 384, "secret123".getBytes(UTF_8), null),
        Arguments.of(KeyPair.ECDSA, 384, "secret123".getBytes(UTF_8), "aes256-gcm@openssh.com"),
        Arguments.of(KeyPair.ECDSA, 384, "secret123".getBytes(UTF_8),
            "chacha20-poly1305@openssh.com"),
        Arguments.of(KeyPair.ECDSA, 521, null, null),
        Arguments.of(KeyPair.ECDSA, 521, "secret123".getBytes(UTF_8), null),
        Arguments.of(KeyPair.ECDSA, 521, "secret123".getBytes(UTF_8), "aes256-gcm@openssh.com"),
        Arguments.of(KeyPair.ECDSA, 521, "secret123".getBytes(UTF_8),
            "chacha20-poly1305@openssh.com"));
  }

  static Stream<Arguments> java15WriteOpenSSHv1KeyArgs() {
    return Stream.of(Arguments.of(KeyPair.ED25519, 0, null, null),
        Arguments.of(KeyPair.ED25519, 0, "secret123".getBytes(UTF_8), null),
        Arguments.of(KeyPair.ED25519, 0, "secret123".getBytes(UTF_8), "aes256-gcm@openssh.com"),
        Arguments.of(KeyPair.ED25519, 0, "secret123".getBytes(UTF_8),
            "chacha20-poly1305@openssh.com"));
  }

  @ParameterizedTest
  @MethodSource("com.jcraft.jsch.KeyPairTest#keyArgs")
  void connectWithPublicKey(String path, String password, String keyType) throws Exception {

    final JSch jSch = createIdentity(path, password);

    Session session = createSession(jSch);

    if (keyType != null) {
      session.setConfig("PubkeyAcceptedAlgorithms", keyType);
    }
    try {
      session.connect(2000);
      assertTrue(session.isConnected());
    } finally {
      session.disconnect();
    }
  }

  @ParameterizedTest
  @MethodSource("com.jcraft.jsch.KeyPairTest#keyArgs")
  void connectWithPublicKeyAndUserInfo(String path, String password, String keyType)
      throws Exception {

    final JSch jSch = new JSch();

    jSch.addIdentity(
        Paths.get(ClassLoader.getSystemResource(path).toURI()).toFile().getAbsolutePath());

    Session session = createSession(jSch);
    session.setUserInfo(new UserInfo() {
      @Override
      public String getPassphrase() {
        return password;
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
        return true;
      }

      @Override
      public boolean promptYesNo(String message) {
        return false;
      }

      @Override
      public void showMessage(String message) {}
    });

    if (keyType != null) {
      session.setConfig("PubkeyAcceptedAlgorithms", keyType);
    }
    try {
      session.connect(2000);
      assertTrue(session.isConnected());
    } finally {
      session.disconnect();
    }
  }

  @ParameterizedTest
  @MethodSource("writeOpenSSHv1KeyArgs")
  void testWriteOpenSSHv1Keys(int type, int key_size, byte[] passphrase, String cipher)
      throws Exception {
    JSch ssh = new JSch();
    KeyPair kp = KeyPair.genKeyPair(ssh, type, key_size);
    String name = kp.getKeyTypeString() + "_" + key_size + "_" + cipher;
    _writeOpenSSHv1Keys(kp, name, passphrase, cipher);
  }

  @ParameterizedTest
  @MethodSource("java15WriteOpenSSHv1KeyArgs")
  @EnabledForJreRange(min = JAVA_15)
  void testJava15WriteOpenSSHv1Keys(int type, int key_size, byte[] passphrase, String cipher)
      throws Exception {
    JSch.setConfig("keypairgen.eddsa", "com.jcraft.jsch.jce.KeyPairGenEdDSA");
    JSch.setConfig("ssh-ed25519", "com.jcraft.jsch.jce.SignatureEd25519");
    JSch ssh = new JSch();
    KeyPair kp = KeyPair.genKeyPair(ssh, type, key_size);
    String name = "java15_" + kp.getKeyTypeString() + "_" + key_size + "_" + cipher;
    _writeOpenSSHv1Keys(kp, name, passphrase, cipher);
  }

  @ParameterizedTest
  @MethodSource("java15WriteOpenSSHv1KeyArgs")
  void testBCWriteOpenSSHv1Keys(int type, int key_size, byte[] passphrase, String cipher)
      throws Exception {
    JSch.setConfig("keypairgen.eddsa", "com.jcraft.jsch.bc.KeyPairGenEdDSA");
    JSch.setConfig("ssh-ed25519", "com.jcraft.jsch.bc.SignatureEd25519");
    JSch ssh = new JSch();
    KeyPair kp = KeyPair.genKeyPair(ssh, type, key_size);
    String name = "bc_" + kp.getKeyTypeString() + "_" + key_size + "_" + cipher;
    _writeOpenSSHv1Keys(kp, name, passphrase, cipher);
  }

  void _writeOpenSSHv1Keys(KeyPair kp, String name, byte[] passphrase, String cipher)
      throws Exception {
    Path foo = tmpDir.resolve(name);
    kp.writeOpenSSHv1PrivateKey(foo.toString(), passphrase, cipher);
    MountableFile f = MountableFile.forHostPath(foo);
    String containerFoo = "/" + foo;
    sshd.copyFileToContainer(f, containerFoo);
    ExecResult result = sshd.execInContainer(UTF_8, "chmod", "600", containerFoo);
    assertEquals(0, result.getExitCode());
    result = sshd.execInContainer(UTF_8, "ssh-keygen", "-y", "-P",
        passphrase != null ? new String(passphrase, UTF_8) : "", "-f", containerFoo);
    try {
      assertEquals(0, result.getExitCode());
    } catch (AssertionError e) {
      System.out.println(result.getStdout());
      System.out.println(result.getStderr());
      System.out.println(foo);
      try {
        Files.readAllLines(foo, UTF_8).forEach(System.out::println);
      } catch (Exception ignore) {
      } finally {
        System.out.println("");
        System.out.println("");
        System.out.println("");
      }
      throw e;
    }
  }

  private JSch createIdentity(String path, String password)
      throws JSchException, URISyntaxException {
    JSch ssh = new JSch();
    if (password != null) {
      ssh.addIdentity(
          Paths.get(ClassLoader.getSystemResource(path).toURI()).toFile().getAbsolutePath(),
          password);
    } else {
      ssh.addIdentity(
          Paths.get(ClassLoader.getSystemResource(path).toURI()).toFile().getAbsolutePath());
    }
    return ssh;
  }

  private Session createSession(JSch ssh) throws Exception {
    Session session = ssh.getSession("root", sshd.getHost(), sshd.getFirstMappedPort());
    session.setConfig("StrictHostKeyChecking", "no");
    session.setConfig("PreferredAuthentications", "publickey");
    return session;
  }
}
