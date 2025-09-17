package com.jcraft.jsch;

import com.github.valfirst.slf4jtest.LoggingEvent;
import com.github.valfirst.slf4jtest.TestLogger;
import com.github.valfirst.slf4jtest.TestLoggerFactory;
import org.apache.commons.codec.digest.DigestUtils;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Locale;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Testcontainers
public class UserCertAuthIT {
  private static final Logger logger = LoggerFactory.getLogger(UserCertAuthIT.class);

  private static final int timeout = 2000;
  private static final DigestUtils sha256sum = new DigestUtils(DigestUtils.getSha256Digest());
  private static final TestLogger jschLogger = TestLoggerFactory.getTestLogger(JSch.class);
  private static final TestLogger sshdLogger =
      TestLoggerFactory.getTestLogger(UserCertAuthIT.class);


  @Container
  public GenericContainer<?> sshd = new GenericContainer<>(new ImageFromDockerfile()
      .withFileFromClasspath("ssh_host_rsa_key", "certificates/docker/ssh_host_rsa_key")
      .withFileFromClasspath("ssh_host_rsa_key.pub", "certificates/docker/ssh_host_rsa_key.pub")
      .withFileFromClasspath("ssh_host_rsa_key-cert.pub",
          "certificates/docker/ssh_host_rsa_key-cert.pub")
      .withFileFromClasspath("ca_jsch_key.pub", "certificates/ca/ca_jsch_key.pub")
      .withFileFromClasspath("sshd_config", "certificates/docker/sshd_config")
      .withFileFromClasspath("Dockerfile", "certificates/docker/Dockerfile")).withExposedPorts(22);


  public static Iterable<? extends String> privateKeyParams() {
    return Arrays.asList(
        // disable dss because dsa algotrithm is deprecated and removed by openssh server
        /* "dss/root_dsa_key", */
        "ecdsa_p256/root_ecdsa_sha2_nistp256_key", "ecdsa_p384/root_ecdsa-sha2-nistp384_key",
        "ecdsa_p521/root_ecdsa_sha2_nistp521_key", "ed25519/root_ed25519_key", "rsa/root_rsa_key");
  }


  @MethodSource("privateKeyParams")
  @ParameterizedTest(name = "key: {0}, cert: {0}-cert.pub")
  public void opensshCertificateParserTest(String privateKey) throws Exception {
    HostKey hostKey = readHostKey(getResourceFile("certificates/docker/ssh_host_rsa_key.pub"));
    JSch ssh = new JSch();
    ssh.addIdentity(getResourceFile("certificates/" + privateKey),
        getResourceFile("certificates/" + privateKey + "-cert.pub"), null);
    ssh.getHostKeyRepository().add(hostKey, null);

    Session session = ssh.getSession("root", sshd.getHost(), sshd.getFirstMappedPort());
    session.setConfig("enable_auth_none", "yes");
    session.setConfig("StrictHostKeyChecking", "no");
    session.setConfig("PreferredAuthentications", "publickey");
    doSftp(session);
  }

  private HostKey readHostKey(String fileName) throws Exception {
    List<String> lines = Files.readAllLines(Paths.get(fileName), UTF_8);
    String[] split = lines.get(0).split("\\s+");
    String hostname = String.format(Locale.ROOT, "[%s]:%d", "localhost", 2222);
    return new HostKey(hostname, Base64.getDecoder().decode(split[1]));
  }


  private void doSftp(Session session) throws Exception {
    assertDoesNotThrow(() -> {
      try {
        session.setTimeout(timeout);
        session.connect();
        ChannelSftp sftp = (ChannelSftp) session.openChannel("sftp");
        sftp.connect(timeout);
        assertTrue(sftp.isConnected());
        sftp.disconnect();
        session.disconnect();
      } catch (Exception e) {
        printInfo();
        throw e;
      }
    });
  }

  private void printInfo() {
    jschLogger.getAllLoggingEvents().stream().map(LoggingEvent::getFormattedMessage)
        .forEach(System.out::println);
    sshdLogger.getAllLoggingEvents().stream().map(LoggingEvent::getFormattedMessage)
        .forEach(System.out::println);
    System.out.println("");
    System.out.println("");
    System.out.println("");
  }

  private String getResourceFile(String fileName) {
    return ResourceUtil.getResourceFile(getClass(), fileName);
  }
}
