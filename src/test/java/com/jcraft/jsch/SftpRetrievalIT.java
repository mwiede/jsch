package com.jcraft.jsch;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.FileOutputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Random;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers
class SftpRetrievalIT {

  private static final int timeout = 10000;

  @TempDir
  public Path tmpDir;
  private Path in;
  private Path out;

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
          .withFileFromClasspath("authorized_keys", "docker/authorized_keys")
          .withFileFromClasspath("Dockerfile", "docker/Dockerfile.asyncssh"))
      .withExposedPorts(22);

  @BeforeEach
  public void beforeEach() throws Exception {
    in = tmpDir.resolve("in");
    out = tmpDir.resolve("out");
    Files.createFile(in);
    try (OutputStream os = Files.newOutputStream(in)) {
      byte[] data = new byte[1024];
      for (int i = 0; i < 1024 * 100; i += 1024) {
        new Random().nextBytes(data);
        os.write(data);
      }
    }
  }

  @Test
  void testDirectoryRetrievalDestinationAsString() throws Exception {
    JSch ssh = createRSAIdentity();
    Session session = createSession(ssh);

    SftpException sftpException = assertThrows(SftpException.class,
        () -> doSftp(session, (sftp) -> sftp.get("/root/", out.toString())));
    assertEquals("not supported to get directory /root/", sftpException.getMessage());
  }

  @Test
  void testDirectoryRetrievalDestinationAsStream() throws Exception {
    JSch ssh = createRSAIdentity();
    Session session = createSession(ssh);

    SftpException sftpException = assertThrows(SftpException.class,
        () -> doSftp(session, (sftp) -> sftp.get("/root/", new FileOutputStream(out.toString()))));
    assertEquals("not supported to get directory /root/", sftpException.getMessage());
  }

  private JSch createRSAIdentity() throws Exception {
    HostKey hostKey = readHostKey(getResourceFile("docker/ssh_host_rsa_key.pub"));
    JSch ssh = new JSch();
    ssh.addIdentity(getResourceFile("docker/id_rsa"), getResourceFile("docker/id_rsa.pub"), null);
    ssh.getHostKeyRepository().add(hostKey, null);
    return ssh;
  }

  private Session createSession(JSch ssh) throws Exception {
    Session session = ssh.getSession("root", sshd.getHost(), sshd.getFirstMappedPort());
    session.setConfig("StrictHostKeyChecking", "yes");
    session.setConfig("PreferredAuthentications", "publickey");
    return session;
  }

  private String getResourceFile(String fileName) {
    return ResourceUtil.getResourceFile(getClass(), fileName);
  }

  private HostKey readHostKey(String fileName) throws Exception {
    List<String> lines = Files.readAllLines(Paths.get(fileName), UTF_8);
    String[] split = lines.get(0).split("\\s+");
    String hostname =
        String.format(Locale.ROOT, "[%s]:%d", sshd.getHost(), sshd.getFirstMappedPort());
    return new HostKey(hostname, Base64.getDecoder().decode(split[1]));
  }

  private void doSftp(Session session, ThrowingConsumer<ChannelSftp, Exception> method)
      throws Exception {
    session.setTimeout(timeout);
    session.connect();
    ChannelSftp sftp = (ChannelSftp) session.openChannel("sftp");
    sftp.connect(timeout);
    sftp.put(in.toString(), "/root/test");
    method.accept(sftp);
    sftp.disconnect();
    session.disconnect();
  }

  @FunctionalInterface
  public interface ThrowingConsumer<T, E extends Exception> {
    void accept(T t) throws E;
  }

}
