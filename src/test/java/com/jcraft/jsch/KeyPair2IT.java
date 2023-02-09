package com.jcraft.jsch;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.net.URISyntaxException;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.assertTrue;

@Testcontainers
public class KeyPair2IT {

  // Python can be slow for DH group 18
  private static final int timeout = 10000;

  @Container
  public GenericContainer<?> sshd = new GenericContainer<>(
      new ImageFromDockerfile().withFileFromClasspath("asyncsshd.py", "docker/asyncsshd.py")
          .withFileFromClasspath("ssh_host_ed448_key", "docker/ssh_host_ed448_key")
          .withFileFromClasspath("ssh_host_ed448_key.pub", "docker/ssh_host_ed448_key.pub")
          .withFileFromClasspath("ssh_host_rsa_key", "docker/ssh_host_rsa_key")
          .withFileFromClasspath("ssh_host_rsa_key.pub", "docker/ssh_host_rsa_key.pub")
          .withFileFromClasspath("ssh_host_ecdsa256_key", "docker/ssh_host_ecdsa256_key")
          .withFileFromClasspath("ssh_host_ecdsa256_key.pub", "docker/ssh_host_ecdsa256_key.pub")
          .withFileFromClasspath("ssh_host_ecdsa384_key", "docker/ssh_host_ecdsa384_key")
          .withFileFromClasspath("ssh_host_ecdsa384_key.pub", "docker/ssh_host_ecdsa384_key.pub")
          .withFileFromClasspath("ssh_host_ecdsa521_key", "docker/ssh_host_ecdsa521_key")
          .withFileFromClasspath("ssh_host_ecdsa521_key.pub", "docker/ssh_host_ecdsa521_key.pub")
          .withFileFromClasspath("ssh_host_ed25519_key", "docker/ssh_host_ed25519_key")
          .withFileFromClasspath("ssh_host_ed25519_key.pub", "docker/ssh_host_ed25519_key.pub")
          .withFileFromClasspath("ssh_host_dsa_key", "docker/ssh_host_dsa_key")
          .withFileFromClasspath("ssh_host_dsa_key.pub", "docker/ssh_host_dsa_key.pub")
          .withFileFromClasspath("authorized_keys", "docker/authorized_keys.KeyPairIT")
          .withFileFromClasspath("Dockerfile", "docker/Dockerfile.asyncssh"))
      .withExposedPorts(22);

  @ParameterizedTest
  @MethodSource("com.jcraft.jsch.KeyPair2Test#keyArgs")
  void connectWithPublicKey(String path, String password, String keyType) throws Exception {

    final JSch jSch = createIdentity(path, password);

    Session session = createSession(jSch);

    if (keyType != null) {
      session.setConfig("PubkeyAcceptedAlgorithms", keyType);
    }
    try {
      session.connect(timeout);
      assertTrue(session.isConnected());
    } finally {
      session.disconnect();
    }

  }

  @ParameterizedTest
  @MethodSource("com.jcraft.jsch.KeyPair2Test#keyArgs")
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
      public void showMessage(String message) {

      }
    });

    if (keyType != null) {
      session.setConfig("PubkeyAcceptedAlgorithms", keyType);
    }
    try {
      session.connect(timeout);
      assertTrue(session.isConnected());
    } finally {
      session.disconnect();
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
