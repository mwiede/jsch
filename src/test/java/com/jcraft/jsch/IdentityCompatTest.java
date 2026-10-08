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
  void testCheckPrivKeyWithNonMatchingPublicPart(String privateK, String publicK, byte[] secret)
      throws Exception {
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
  void testCheckPrivKeyWithNonMatchingUserCertB(String privateK, String publicK, byte[] secret)
      throws Exception {
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
