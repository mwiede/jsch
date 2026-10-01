package com.jcraft.jsch;

import static com.jcraft.jsch.ResourceUtil.getResourceFile;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for openssh certificate key compatibility: does public key signed by certificate match
 * private key
 */
public class OpenSshCertificateKeyCompatTest {

  @Test
  /**
   * Test that adding an identity of a private key with matching user certificate succeeds
   */
  public void testCheckPrivKeyWithMatchingUserCert() throws Exception {
    JSch jsch = new JSch();
    jsch.addIdentity(getResourceFile("certificates/ed25519/root_ed25519_key"),
        getResourceFile("certificates/ed25519/root_ed25519_key-cert.pub"), null);
  }

  @Test
  /**
   * Test that adding an identity of a private key with unmatching user certificate fails
   */
  public void testCheckPrivKeyWithNonMatchingUserCert() throws Exception {
    JSch jsch = new JSch();
    assertThrows(JSchException.class,

        () -> jsch.addIdentity(getResourceFile("docker/id_ed25519"),
            getResourceFile("certificates/ed25519/root_ed25519_key-cert.pub"), null));
  }

  @Test
  /**
   * Test that adding an identity of a private key with matching public key succeeds
   */
  public void testCheckPrivKeyWithMatchingPubKey() throws Exception {
    JSch jsch = new JSch();
    jsch.addIdentity(getResourceFile("docker/id_ed25519"), getResourceFile("docker/id_ed25519.pub"),
        null);
  }

  @Test
  /**
   * Test that adding an identity of a private key with non-matching public key fails
   */
  public void testCheckPrivKeyWithNonMatchingPubKey() throws Exception {
    JSch jsch = new JSch();
    assertThrows(JSchException.class,

        () -> jsch.addIdentity(getResourceFile("docker/id_ed25519"),
            getResourceFile("certificates/ed25519/root_ed25519_key.pub"), null));
  }

  @Test
  /**
   * Test that adding an identity of a private key with something that is neither a public key nor a
   * certificate fails
   */
  public void testCheckPrivKeyWithNonPubKey() throws Exception {
    JSch jsch = new JSch();
    assertThrows(JSchException.class,

        () -> jsch.addIdentity(getResourceFile("docker/id_ed25519"),
            getResourceFile("certificates/host/sshd_config"), null));
  }


  private String getResourceFile(String fileName) {
    return ResourceUtil.getResourceFile(getClass(), fileName);
  }
}
