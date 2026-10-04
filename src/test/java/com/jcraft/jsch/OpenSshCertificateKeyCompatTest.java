package com.jcraft.jsch;

import static com.jcraft.jsch.ResourceUtil.getResourceFile;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * Unit tests for openssh certificate key compatibility: does public key signed by certificate match
 * private key
 */
public class OpenSshCertificateKeyCompatTest {

  /**
   * Test that adding an identity of a private key with matching user certificate or public key
   * succeeds, file name version
   */
  @ParameterizedTest(name = "File private key {0} is compatible with {1} certificate or public key")
  @CsvSource({
      "'certificates/ed25519/root_ed25519_key','certificates/ed25519/root_ed25519_key-cert.pub'",
      "'docker/id_ed25519','docker/id_ed25519.pub'"})
  void testCheckPrivKeyWithMatchingUserCert(String privateK, String publicK) throws Exception {
    JSch jsch = new JSch();
    jsch.addIdentity(getResourceFile(privateK), getResourceFile(publicK), null);
  }

  /**
   * Test that adding an identity of a private key with matching user certificate or public key
   * succeeds, byte array version
   */
  @ParameterizedTest(
      name = "Byte[] private key {0} is compatible with {1} certificate or public key")
  @CsvSource({
      "'certificates/ed25519/root_ed25519_key','certificates/ed25519/root_ed25519_key-cert.pub'",
      "'docker/id_ed25519','docker/id_ed25519.pub'"})
  void testCheckPrivKeyWithMatchingUserCertB(String privateK, String publicK) throws Exception {
    JSch jsch = new JSch();
    jsch.addIdentity("test", getResourceBytes(privateK), getResourceBytes(publicK), null);
  }

  /**
   * Test that adding an identity of a private key with unmatching user certificate or public key
   * fails
   */
  @ParameterizedTest(
      name = "File private key {0} is incompatible with {1} certificate or public key")
  @CsvSource({"'docker/id_ed25519','certificates/ed25519/root_ed25519_key-cert.pub'",
      "'docker/id_ed25519','certificates/ed25519/root_ed25519_key.pub'",
      "'docker/id_ed25519','certificates/host/sshd_config'"})
  void testCheckPrivKeyWithNonMatchingUserCert(String privateK, String publicK) throws Exception {
    JSch jsch = new JSch();
    assertThrows(JSchException.class,

        () -> jsch.addIdentity(getResourceFile(privateK), getResourceFile(publicK), null));
  }

  /**
   * Test that adding an identity of a private key with unmatching public key or user certificate
   * fails
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
