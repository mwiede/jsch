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
public class KeyPairIT {

  @Container
  public GenericContainer<?> sshd = new GenericContainer<>(
      new ImageFromDockerfile().withFileFromClasspath("sshd_config", "docker/sshd_config")
          .withFileFromClasspath("authorized_keys", "docker/authorized_keys.KeyPairIT")
          .withFileFromClasspath("Dockerfile", "docker/Dockerfile.KeyPairIT"))
      .withExposedPorts(22);

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
      public void showMessage(String message) {

      }
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
