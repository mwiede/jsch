package com.jcraft.jsch;

import static com.jcraft.jsch.ResourceUtil.getResourceFile;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Unit tests for compatibility between the private and public (key or certificate) part of an
 * identity
 */
public class IdentityCompatTest {

  static Stream<Arguments> keyArgs() {
    return Stream.of(
        Arguments.of("certificates/ed25519/root_ed25519_key",
            "certificates/ed25519/root_ed25519_key-cert.pub", null),
        Arguments.of("docker/id_ed25519", "docker/id_ed25519.pub", null),

        // PKCS8
        Arguments.of("pkcs8_rsa_encrypted_hmacsha256", "pkcs8_rsa_encrypted_hmacsha256.pub",
            "secret123".getBytes(UTF_8)),
        Arguments.of("pkcs8_rsa_encrypted_hmacsha256", "pkcs8_rsa_encrypted_hmacsha256-cert.pub",
            "secret123".getBytes(UTF_8)),

        // full coverage...
        Arguments.of("certificates/asyncssh_host/id_ecdsa_nistp521",
            "certificates/asyncssh_host/id_ecdsa_nistp521.pub", null),
        Arguments.of("certificates/asyncssh_host/ssh_host_ed448_key",
            "certificates/asyncssh_host/ssh_host_ed448_key-cert.pub", null),
        Arguments.of("certificates/asyncssh_host/ssh_host_ed448_key",
            "certificates/asyncssh_host/ssh_host_ed448_key.pub", null),
        Arguments.of("certificates/asyncssh_user/root_ed448_key",
            "certificates/asyncssh_user/root_ed448_key-cert.pub", null),
        Arguments.of("certificates/asyncssh_user/root_ed448_key",
            "certificates/asyncssh_user/root_ed448_key.pub", null),
        Arguments.of("certificates/asyncssh_user/ssh_host_ed25519_key",
            "certificates/asyncssh_user/ssh_host_ed25519_key.pub", null),
        Arguments.of("certificates/docker/ssh_host_rsa_key",
            "certificates/docker/ssh_host_rsa_key-cert.pub", null),
        Arguments.of("certificates/docker/ssh_host_rsa_key",
            "certificates/docker/ssh_host_rsa_key.pub", null),
        Arguments.of("certificates/dss/root_dsa_key", "certificates/dss/root_dsa_key-cert.pub",
            null),
        Arguments.of("certificates/dss/root_dsa_key", "certificates/dss/root_dsa_key.pub", null),
        Arguments.of("certificates/dss_host/id_ecdsa_nistp521",
            "certificates/dss_host/id_ecdsa_nistp521.pub", null),
        Arguments.of("certificates/dss_host/ssh_host_dsa_key",
            "certificates/dss_host/ssh_host_dsa_key-cert.pub", null),
        Arguments.of("certificates/dss_host/ssh_host_dsa_key",
            "certificates/dss_host/ssh_host_dsa_key.pub", null),
        Arguments.of("certificates/ecdsa_p256/root_ecdsa_sha2_nistp256_key",
            "certificates/ecdsa_p256/root_ecdsa_sha2_nistp256_key-cert.pub", null),
        Arguments.of("certificates/ecdsa_p256/root_ecdsa_sha2_nistp256_key",
            "certificates/ecdsa_p256/root_ecdsa_sha2_nistp256_key.pub", null),
        Arguments.of("certificates/ecdsa_p384/root_ecdsa-sha2-nistp384_key",
            "certificates/ecdsa_p384/root_ecdsa-sha2-nistp384_key-cert.pub", null),
        Arguments.of("certificates/ecdsa_p521/root_ecdsa_sha2_nistp521_key",
            "certificates/ecdsa_p521/root_ecdsa_sha2_nistp521_key-cert.pub", null),
        Arguments.of("certificates/ecdsa_p521/root_ecdsa_sha2_nistp521_key",
            "certificates/ecdsa_p521/root_ecdsa_sha2_nistp521_key.pub", null),
        Arguments.of("certificates/ed25519/root_ed25519_key",
            "certificates/ed25519/root_ed25519_key-cert.pub", null),
        Arguments.of("certificates/ed25519/root_ed25519_key",
            "certificates/ed25519/root_ed25519_key.pub", null),
        Arguments.of("certificates/host/ssh_host_dsa_key", "certificates/host/ssh_host_dsa_key.pub",
            null),
        Arguments.of("certificates/host/ssh_host_ecdsa_key",
            "certificates/host/ssh_host_ecdsa_key-cert.pub", null),
        Arguments.of("certificates/host/ssh_host_ecdsa_key",
            "certificates/host/ssh_host_ecdsa_key.pub", null),
        Arguments.of("certificates/host/ssh_host_ed25519_key",
            "certificates/host/ssh_host_ed25519_key-cert.pub", null),
        Arguments.of("certificates/host/ssh_host_ed25519_key",
            "certificates/host/ssh_host_ed25519_key.pub", null),
        Arguments.of("certificates/host/ssh_host_rsa_key",
            "certificates/host/ssh_host_rsa_key-cert.pub", null),
        Arguments.of("certificates/host/ssh_host_rsa_key", "certificates/host/ssh_host_rsa_key.pub",
            null),
        Arguments.of("certificates/host/user_keys/id_ecdsa_nistp521",
            "certificates/host/user_keys/id_ecdsa_nistp521.pub", null),
        Arguments.of("certificates/rsa/root_rsa_key", "certificates/rsa/root_rsa_key-cert.pub",
            null),
        Arguments.of("certificates/rsa/root_rsa_key", "certificates/rsa/root_rsa_key.pub", null),
        Arguments.of("docker/id_dsa", "docker/id_dsa.pub", null),
        Arguments.of("docker/id_ecdsa256", "docker/id_ecdsa256.pub", null),
        Arguments.of("docker/id_ecdsa384", "docker/id_ecdsa384.pub", null),
        Arguments.of("docker/id_ecdsa521", "docker/id_ecdsa521.pub", null),
        Arguments.of("docker/id_ed25519", "docker/id_ed25519.pub", null),
        Arguments.of("docker/id_ed448", "docker/id_ed448.pub", null),
        Arguments.of("docker/id_rsa", "docker/id_rsa.pub", null),
        Arguments.of("docker/ssh_host_dsa_key", "docker/ssh_host_dsa_key.pub", null),
        Arguments.of("docker/ssh_host_ecdsa256_key", "docker/ssh_host_ecdsa256_key.pub", null),
        Arguments.of("docker/ssh_host_ecdsa384_key", "docker/ssh_host_ecdsa384_key.pub", null),
        Arguments.of("docker/ssh_host_ecdsa521_key", "docker/ssh_host_ecdsa521_key.pub", null),
        Arguments.of("docker/ssh_host_ed25519_key", "docker/ssh_host_ed25519_key.pub", null),
        Arguments.of("docker/ssh_host_ed448_key", "docker/ssh_host_ed448_key.pub", null),
        Arguments.of("docker/ssh_host_rsa_key", "docker/ssh_host_rsa_key.pub", null),
        Arguments.of("encrypted_issue_369_rsa_opensshv1", "encrypted_issue_369_rsa_opensshv1.pub",
            "secret123".getBytes(UTF_8)),
        Arguments.of("encrypted_issue_369_rsa_pem", "encrypted_issue_369_rsa_pem.pub",
            "secret123".getBytes(UTF_8)),
        Arguments.of("encrypted_openssh_private_key_dsa", "encrypted_openssh_private_key_dsa.pub",
            "secret123".getBytes(UTF_8)),
        Arguments.of("encrypted_openssh_private_key_dsa_aes256gcm",
            "encrypted_openssh_private_key_dsa_aes256gcm.pub", "secret123".getBytes(UTF_8)),
        Arguments.of("encrypted_openssh_private_key_dsa_chacha20poly1305",
            "encrypted_openssh_private_key_dsa_chacha20poly1305.pub", "secret123".getBytes(UTF_8)),
        Arguments.of("encrypted_openssh_private_key_ecdsa",
            "encrypted_openssh_private_key_ecdsa.pub", "secret123".getBytes(UTF_8)),
        Arguments.of("encrypted_openssh_private_key_ecdsa_aes256gcm",
            "encrypted_openssh_private_key_ecdsa_aes256gcm.pub", "secret123".getBytes(UTF_8)),
        Arguments.of("encrypted_openssh_private_key_ecdsa_chacha20poly1305",
            "encrypted_openssh_private_key_ecdsa_chacha20poly1305.pub",
            "secret123".getBytes(UTF_8)),
        Arguments.of("encrypted_openssh_private_key_ed25519",
            "encrypted_openssh_private_key_ed25519.pub", "secret123".getBytes(UTF_8)),
        Arguments.of("encrypted_openssh_private_key_ed25519_aes256gcm",
            "encrypted_openssh_private_key_ed25519_aes256gcm.pub", "secret123".getBytes(UTF_8)),
        Arguments.of("encrypted_openssh_private_key_ed25519_chacha20poly1305",
            "encrypted_openssh_private_key_ed25519_chacha20poly1305.pub",
            "secret123".getBytes(UTF_8)),
        Arguments.of("encrypted_openssh_private_key_rsa", "encrypted_openssh_private_key_rsa.pub",
            "secret123".getBytes(UTF_8)),
        Arguments.of("encrypted_openssh_private_key_rsa_aes256gcm",
            "encrypted_openssh_private_key_rsa_aes256gcm.pub", "secret123".getBytes(UTF_8)),
        Arguments.of("encrypted_openssh_private_key_rsa_chacha20poly1305",
            "encrypted_openssh_private_key_rsa_chacha20poly1305.pub", "secret123".getBytes(UTF_8)),
        Arguments.of("issue362_rsa", "issue362_rsa.pub", "secret123".getBytes(UTF_8)),
        Arguments.of("issue_369_rsa_opensshv1", "issue_369_rsa_opensshv1.pub", null),
        Arguments.of("issue_369_rsa_pem", "issue_369_rsa_pem.pub", null),
        Arguments.of("pkcs8_dsa", "pkcs8_dsa.pub", null),
        Arguments.of("pkcs8_dsa_encrypted_hmacsha1", "pkcs8_dsa_encrypted_hmacsha1.pub",
            "secret123".getBytes(UTF_8)),
        Arguments.of("pkcs8_dsa_encrypted_hmacsha256", "pkcs8_dsa_encrypted_hmacsha256.pub",
            "secret123".getBytes(UTF_8)),
        Arguments.of("pkcs8_ecdsa256", "pkcs8_ecdsa256.pub", null),
        Arguments.of("pkcs8_ecdsa256_encrypted_scrypt", "pkcs8_ecdsa256_encrypted_scrypt.pub",
            "secret123".getBytes(UTF_8)),
        Arguments.of("pkcs8_ecdsa384", "pkcs8_ecdsa384.pub", null),
        Arguments.of("pkcs8_ecdsa384_encrypted_scrypt", "pkcs8_ecdsa384_encrypted_scrypt.pub",
            "secret123".getBytes(UTF_8), "secret123".getBytes(UTF_8)),
        Arguments.of("pkcs8_ecdsa521", "pkcs8_ecdsa521.pub", null),
        Arguments.of("pkcs8_ecdsa521_encrypted_scrypt", "pkcs8_ecdsa521_encrypted_scrypt.pub",
            "secret123".getBytes(UTF_8)),
        Arguments.of("pkcs8_ed25519", "pkcs8_ed25519.pub", null),
        Arguments.of("pkcs8_ed25519_encrypted_scrypt", "pkcs8_ed25519_encrypted_scrypt.pub",
            "secret123".getBytes(UTF_8)),
        Arguments.of("pkcs8_ed448", "pkcs8_ed448.pub", null),
        Arguments.of("pkcs8_ed448_encrypted_scrypt", "pkcs8_ed448_encrypted_scrypt.pub",
            "secret123".getBytes(UTF_8)),
        Arguments.of("pkcs8_rsa", "pkcs8_rsa.pub", null),
        Arguments.of("pkcs8_rsa_encrypted_hmacsha1", "pkcs8_rsa_encrypted_hmacsha1.pub",
            "secret123".getBytes(UTF_8)),
        Arguments.of("pkcs8_rsa_encrypted_hmacsha256", "pkcs8_rsa_encrypted_hmacsha256-cert.pub",
            "secret123".getBytes(UTF_8)),
        Arguments.of("pkcs8_rsa_encrypted_hmacsha256", "pkcs8_rsa_encrypted_hmacsha256.pub",
            "secret123".getBytes(UTF_8)));
  }

  /**
   * Test that adding an identity of a private key with matching public part (certificate or public
   * key) succeeds, file name version
   */
  @ParameterizedTest(name = "File private key {0} is compatible with {1} certificate or public key")
  @MethodSource("keyArgs")
  void testCheckPrivKeyWithMatchingPublicPart(String privateK, String publicK, byte[] secret)
      throws Exception {
    JSch jsch = new JSch();
    jsch.addIdentity(getResourceFile(privateK), getResourceFile(publicK), secret);
  }

  /**
   * Test that adding an identity of a private key with matching public part (certificate or public
   * key) succeeds, byte array version
   */
  @ParameterizedTest(
      name = "Byte[] private key {0} is compatible with {1} certificate or public key")
  @MethodSource("keyArgs")
  void testCheckPrivKeyWithMatchingPublicPartB(String privateK, String publicK, byte[] secret)
      throws Exception {
    JSch jsch = new JSch();
    jsch.addIdentity("test", getResourceBytes(privateK), getResourceBytes(publicK), secret);
  }

  static Stream<Arguments> keyArgsNonMatching() {
    return Stream.of(
        Arguments.of("docker/id_ed25519", "certificates/ed25519/root_ed25519_key-cert.pub", null),
        Arguments.of("docker/id_ed25519", "certificates/ed25519/root_ed25519_key.pub", null),
        Arguments.of("docker/id_ed25519", "certificates/host/sshd_config", null),

        Arguments.of("pkcs8_rsa_encrypted_hmacsha256",
            "certificates/ed25519/root_ed25519_key-cert.pub", "secret123".getBytes(UTF_8)),
        Arguments.of("pkcs8_rsa_encrypted_hmacsha256", "certificates/ed25519/root_ed25519_key.pub",
            "secret123".getBytes(UTF_8)),
        Arguments.of("pkcs8_rsa_encrypted_hmacsha256", "certificates/host/sshd_config",
            "secret123".getBytes(UTF_8)));
  }

  /**
   * Test that adding an identity of a private key with non-matching public part (certificate or
   * public key) fails, file name version
   */
  @ParameterizedTest(
      name = "File private key {0} is incompatible with {1} certificate or public key")
  @MethodSource("keyArgsNonMatching")
  void testCheckPrivKeyWithNonMatchingPublicPart(String privateK, String publicK, byte[] secret) {
    JSch jsch = new JSch();
    assertThrows(JSchException.class,

        () -> jsch.addIdentity(getResourceFile(privateK), getResourceFile(publicK), secret));
  }

  /**
   * Test that adding an identity of a private key with non-matching public part (certificate or
   * public key) fails, byte array version version
   */
  @ParameterizedTest(
      name = "Byte[] private key {0} is incompatible with {1} certificate or public key")
  @MethodSource("keyArgsNonMatching")
  void testCheckPrivKeyWithNonMatchingUserCertB(String privateK, String publicK, byte[] secret) {
    JSch jsch = new JSch();
    assertThrows(JSchException.class, () -> jsch.addIdentity("test", getResourceBytes(privateK),
        getResourceBytes(publicK), secret));
  }

  private String getResourceFile(String fileName) {
    return ResourceUtil.getResourceFile(getClass(), fileName);
  }

  private byte[] getResourceBytes(String fileName) throws java.io.IOException {
    return Util.fromFile(ResourceUtil.getResourceFile(getClass(), fileName));
  }
}
