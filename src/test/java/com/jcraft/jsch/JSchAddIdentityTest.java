package com.jcraft.jsch;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Vector;
import org.junit.jupiter.api.Test;

public class JSchAddIdentityTest {

  private static final String CERTIFICATES_BASE = "src/test/resources/certificates";

  /**
   * Tests that addIdentity(prvkey, null, passphrase) auto-discovers the certificate file when a
   * file named prvkey + "-cert.pub" exists.
   */
  @Test
  void addIdentity_withNullPubkey_shouldAutoDiscoverCertificate() throws Exception {
    JSch jsch = new JSch();

    // Private key file: root_ed25519_key
    // Certificate file: root_ed25519_key-cert.pub (should be auto-discovered)
    String prvkey = CERTIFICATES_BASE + "/ed25519/root_ed25519_key";

    // Call with pubkey = null, should auto-discover the -cert.pub file
    jsch.addIdentity(prvkey, null, null);

    // Verify that an identity was added
    IdentityRepository repo = jsch.getIdentityRepository();
    Vector<Identity> identities = repo.getIdentities();

    assertNotNull(identities);
    assertEquals(1, identities.size());

    Identity identity = identities.get(0);
    // Verify it's a certificate-aware identity by checking the algorithm name
    String algName = identity.getAlgName();
    assertTrue(algName.contains("-cert-v01@openssh.com"),
        "Expected certificate algorithm, got: " + algName);
  }

  /**
   * Tests that addIdentity(prvkey, null, passphrase) falls back to regular behavior when no
   * certificate file exists (only .pub file).
   */
  @Test
  void addIdentity_withNullPubkey_shouldFallbackWhenNoCertificate() throws Exception {
    JSch jsch = new JSch();

    // Use a key that has only .pub file, not -cert.pub
    // For this test, we need a key without a certificate
    // We'll use a temporary approach - create the scenario or use existing non-cert key
    String prvkey = CERTIFICATES_BASE + "/host/user_keys/id_ecdsa_nistp521";

    // This key has .pub but not -cert.pub, should fall back to IdentityFile
    jsch.addIdentity(prvkey, null, null);

    // Verify that an identity was added
    IdentityRepository repo = jsch.getIdentityRepository();
    Vector<Identity> identities = repo.getIdentities();

    assertNotNull(identities);
    assertEquals(1, identities.size());

    Identity identity = identities.get(0);
    // Should NOT be a certificate algorithm
    String algName = identity.getAlgName();
    assertFalse(algName.contains("-cert-v01@openssh.com"),
        "Expected non-certificate algorithm, got: " + algName);
  }

  /**
   * Tests that addIdentity with explicit pubkey path still works correctly for certificate files.
   */
  @Test
  void addIdentity_withExplicitCertPubkey_shouldLoadCertificate() throws Exception {
    JSch jsch = new JSch();

    String prvkey = CERTIFICATES_BASE + "/ed25519/root_ed25519_key";
    String pubkey = CERTIFICATES_BASE + "/ed25519/root_ed25519_key-cert.pub";

    jsch.addIdentity(prvkey, pubkey, null);

    IdentityRepository repo = jsch.getIdentityRepository();
    Vector<Identity> identities = repo.getIdentities();

    assertNotNull(identities);
    assertEquals(1, identities.size());

    Identity identity = identities.get(0);
    String algName = identity.getAlgName();
    assertEquals("ssh-ed25519-cert-v01@openssh.com", algName);
  }

  /**
   * Tests that addIdentity throws an exception when an explicitly provided pubkey file does not
   * exist. This matches KeyPair.load() behavior.
   */
  @Test
  void addIdentity_withExplicitNonExistentPubkey_shouldThrowException() {
    JSch jsch = new JSch();

    String prvkey = CERTIFICATES_BASE + "/ed25519/root_ed25519_key";
    String pubkey = CERTIFICATES_BASE + "/ed25519/non_existent_file.pub";

    assertThrows(JSchException.class, () -> jsch.addIdentity(prvkey, pubkey, null),
        "Should throw JSchException when explicitly provided pubkey file does not exist");
  }

  /**
   * Tests that addIdentity does NOT throw an exception when auto-discovered certificate file does
   * not exist. This matches KeyPair.load() behavior where auto-discovery failures are silently
   * ignored.
   */
  @Test
  void addIdentity_withNullPubkeyAndNoCertFile_shouldNotThrowException() throws Exception {
    JSch jsch = new JSch();

    // This key has only .pub file, no -cert.pub file
    // Auto-discovery of -cert.pub should fail silently
    String prvkey = CERTIFICATES_BASE + "/host/user_keys/id_ecdsa_nistp521";

    // Should not throw - auto-discovery failure is silent
    jsch.addIdentity(prvkey, null, null);

    // Verify that an identity was still added (via IdentityFile fallback)
    IdentityRepository repo = jsch.getIdentityRepository();
    Vector<Identity> identities = repo.getIdentities();

    assertNotNull(identities);
    assertEquals(1, identities.size());
  }
}
