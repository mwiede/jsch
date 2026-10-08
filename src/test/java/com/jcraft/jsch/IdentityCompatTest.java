package com.jcraft.jsch;

import static com.jcraft.jsch.ResourceUtil.getResourceFile;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * Unit tests for compatibility between the private and public (key or certificate) part of an
 * identity
 */
public class IdentityCompatTest {

  /**
   * Test that adding an identity of a private key with matching public part (certificate or public
   * key) succeeds, file name version
   */
  @ParameterizedTest(name = "File private key {0} is compatible with {1} certificate or public key")
  @CsvSource({
      "'certificates/ed25519/root_ed25519_key','certificates/ed25519/root_ed25519_key-cert.pub'",
      "'docker/id_ed25519','docker/id_ed25519.pub'"})
  void testCheckPrivKeyWithMatchingPublicPart(String privateK, String publicK) throws Exception {
    JSch jsch = new JSch();
    jsch.addIdentity(getResourceFile(privateK), getResourceFile(publicK), null);
  }

  /**
   * Test that adding an identity of a private key with matching public part (certificate or public
   * key) succeeds, byte array version
   */
  @ParameterizedTest(
      name = "Byte[] private key {0} is compatible with {1} certificate or public key")
  @CsvSource({
      "'certificates/ed25519/root_ed25519_key','certificates/ed25519/root_ed25519_key-cert.pub'",
      "'docker/id_ed25519','docker/id_ed25519.pub'"})
  void testCheckPrivKeyWithMatchingPublicPartB(String privateK, String publicK) throws Exception {
    JSch jsch = new JSch();
    jsch.addIdentity("test", getResourceBytes(privateK), getResourceBytes(publicK), null);
  }

  /**
   * Test that adding an identity of a private key with matching public part (certificate or public
   * key) succeeds, file name version, PKCS8
   */
  @ParameterizedTest(name = "File private key {0} is compatible with {1} certificate or public key")
  @CsvSource({
      "'pkcs8_rsa_encrypted_hmacsha256','pkcs8_rsa_encrypted_hmacsha256.pub'",
      "'pkcs8_rsa_encrypted_hmacsha256','pkcs8_rsa_encrypted_hmacsha256-cert.pub'"})
  void testCheckPKCS8PrivKeyWithMatchingPublicPart(String privateK, String publicK) throws Exception {
    JSch jsch = new JSch();
    jsch.addIdentity(getResourceFile(privateK), getResourceFile(publicK),
		     "secret123".getBytes(UTF_8));
  }

  /**
   * Test that adding an identity of a private key with non-matching public part (certificate or
   * public key) fails, file name version
   */
  @ParameterizedTest(
      name = "File private key {0} is incompatible with {1} certificate or public key")
  @CsvSource({"'docker/id_ed25519','certificates/ed25519/root_ed25519_key-cert.pub'",
      "'docker/id_ed25519','certificates/ed25519/root_ed25519_key.pub'",
      "'docker/id_ed25519','certificates/host/sshd_config'"})
  void testCheckPrivKeyWithNonMatchingPublicPart(String privateK, String publicK) throws Exception {
    JSch jsch = new JSch();
    assertThrows(JSchException.class,

        () -> jsch.addIdentity(getResourceFile(privateK), getResourceFile(publicK), null));
  }

  /**
   * Test that adding an identity of a private key with non-matching public part (certificate or
   * public key) fails, file name version, PKCS8
   */
  @ParameterizedTest(
      name = "File private key {0} is incompatible with {1} certificate or public key")
  @CsvSource({"'pkcs8_rsa_encrypted_hmacsha256','certificates/ed25519/root_ed25519_key-cert.pub'",
      "'pkcs8_rsa_encrypted_hmacsha256','certificates/ed25519/root_ed25519_key.pub'",
      "'pkcs8_rsa_encrypted_hmacsha256','certificates/host/sshd_config'"})
  void testCheckPKCS8PrivKeyWithNonMatchingPublicPart(String privateK, String publicK) throws Exception {
    JSch jsch = new JSch();
    assertThrows(JSchException.class,

        () -> jsch.addIdentity(getResourceFile(privateK), getResourceFile(publicK), "secret123".getBytes(UTF_8)));
  }

  /**
   * Test that adding an identity of a private key with non-matching public part (certificate or
   * public key) fails, byte array version version
   */
  @ParameterizedTest(
      name = "Byte[] private key {0} is incompatible with {1} certificate or public key")
  @CsvSource({"'docker/id_ed25519','certificates/ed25519/root_ed25519_key-cert.pub'",
      "'docker/id_ed25519','certificates/ed25519/root_ed25519_key.pub'",
      "'docker/id_ed25519','certificates/host/sshd_config'"})
  void testCheckPrivKeyWithNonMatchingUserCertB(String privateK, String publicK) throws Exception {
    JSch jsch = new JSch();
    assertThrows(JSchException.class, () -> jsch.addIdentity("test", getResourceBytes(privateK),
        getResourceBytes(publicK), null));
  }

  private String getResourceFile(String fileName) {
    return ResourceUtil.getResourceFile(getClass(), fileName);
  }

  private byte[] getResourceBytes(String fileName) throws java.io.IOException {
    return Util.fromFile(ResourceUtil.getResourceFile(getClass(), fileName));
  }
}
