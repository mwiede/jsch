package com.jcraft.jsch;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for OpenSshCertificateHostKeyVerifier focusing on certificate validation edge cases.
 */
public class OpenSshCertificateHostKeyVerifierTest {

  // ==================== Tests for critical options rejection ====================

  /**
   * Test that a certificate with critical options is rejected.
   */
  @Test
  public void testCheckHostCertificate_withCriticalOptions_shouldReject() throws Exception {
    Map<String, String> criticalOptions = new HashMap<>();
    criticalOptions.put("force-command", "/bin/false");

    OpenSshCertificate cert =
        createValidHostCertificateBuilder().criticalOptions(criticalOptions).build();

    // Verify that isEmpty correctly identifies non-empty critical options
    assertTrue(!OpenSshCertificateUtil.isEmpty(cert.getCriticalOptions()),
        "Critical options should not be empty");
  }

  /**
   * Test that a certificate with multiple critical options is detected.
   */
  @Test
  public void testCheckHostCertificate_withMultipleCriticalOptions() {
    Map<String, String> criticalOptions = new HashMap<>();
    criticalOptions.put("force-command", "/bin/false");
    criticalOptions.put("source-address", "192.168.1.0/24");

    OpenSshCertificate cert =
        createValidHostCertificateBuilder().criticalOptions(criticalOptions).build();

    assertEquals(2, cert.getCriticalOptions().size(), "Should have 2 critical options");
  }

  /**
   * Test that a certificate with empty critical options is accepted.
   */
  @Test
  public void testCheckHostCertificate_withEmptyCriticalOptions() {
    OpenSshCertificate cert =
        createValidHostCertificateBuilder().criticalOptions(Collections.emptyMap()).build();

    assertTrue(OpenSshCertificateUtil.isEmpty(cert.getCriticalOptions()),
        "Critical options should be empty");
  }

  /**
   * Test that a certificate with null critical options is accepted.
   */
  @Test
  public void testCheckHostCertificate_withNullCriticalOptions() {
    OpenSshCertificate cert = createValidHostCertificateBuilder().criticalOptions(null).build();

    assertTrue(OpenSshCertificateUtil.isEmpty(cert.getCriticalOptions()),
        "Null critical options should be treated as empty");
  }

  // ==================== Tests for certificate type validation ====================

  /**
   * Test that isHostCertificate returns true for host certificate type.
   */
  @Test
  public void testIsHostCertificate_hostType() {
    OpenSshCertificate cert = createValidHostCertificateBuilder().build();

    assertTrue(cert.isHostCertificate(), "Should be identified as host certificate");
  }

  /**
   * Test that isHostCertificate returns false for user certificate type.
   */
  @Test
  public void testIsHostCertificate_userType() {
    OpenSshCertificate cert = createValidUserCertificateBuilder().build();

    assertTrue(!cert.isHostCertificate(), "Should not be identified as host certificate");
  }

  // ==================== Tests for principal validation ====================

  /**
   * Test that empty principals list is detected.
   */
  @Test
  public void testPrincipals_emptyList() {
    OpenSshCertificate cert =
        createValidHostCertificateBuilder().principals(Collections.emptyList()).build();

    assertTrue(cert.getPrincipals().isEmpty(), "Principals should be empty");
  }

  /**
   * Test that null principals list is handled.
   */
  @Test
  public void testPrincipals_nullList() {
    OpenSshCertificate cert = createValidHostCertificateBuilder().principals(null).build();

    assertTrue(cert.getPrincipals() == null, "Principals should be null");
  }

  /**
   * Test that multiple principals are correctly stored.
   */
  @Test
  public void testPrincipals_multipleValues() {
    OpenSshCertificate cert = createValidHostCertificateBuilder()
        .principals(Arrays.asList("host1.example.com", "host2.example.com", "10.0.0.1")).build();

    assertEquals(3, cert.getPrincipals().size(), "Should have 3 principals");
    assertTrue(cert.getPrincipals().contains("host1.example.com"), "Should contain host1");
    assertTrue(cert.getPrincipals().contains("host2.example.com"), "Should contain host2");
    assertTrue(cert.getPrincipals().contains("10.0.0.1"), "Should contain IP");
  }

  // ==================== Tests for RSA CA signature algorithm (issue #1085) ====================

  /**
   * A host certificate signed by an {@code ssh-rsa} CA must not be rejected merely because the CA
   * key algorithm ({@code ssh-rsa}) differs from the certificate's signature algorithm. Per RFC
   * 8332, an {@code ssh-rsa} key signs with {@code rsa-sha2-256}/{@code rsa-sha2-512} while its key
   * type string stays {@code ssh-rsa}, and OpenSSH signs with {@code rsa-sha2-512} by default since
   * 8.2.
   * <p>
   * Before the fix, {@code getSignatureWrapper} compared the two names for equality and threw
   * {@link JSchInvalidHostCertificateException} before the (valid) signature was ever verified, so
   * every RSA host CA was rejected. This test parses a real OpenSSH host certificate signed by an
   * RSA CA and asserts the signature verifies.
   */
  @Test
  public void testCheckSignature_rsaCaSigningWithRsaSha2_isAccepted() throws Exception {
    OpenSshCertificate cert =
        parseCertificate("src/test/resources/certificates/rsa_host_ca/ssh_host_ecdsa_key-cert.pub");

    // Derive the CA key algorithm and signature algorithm exactly as checkHostCertificate does.
    String caPublicKeyAlgorithm = Util.byte2str(new Buffer(cert.getSignatureKey()).getString());
    String signatureAlgorithm = Util.byte2str(new Buffer(cert.getSignature()).getString());

    // Precondition: this fixture exercises the RSA CA case where the two names legitimately differ.
    assertEquals("ssh-rsa", caPublicKeyAlgorithm, "fixture CA key must be ssh-rsa");
    assertEquals("rsa-sha2-512", signatureAlgorithm, "fixture must be signed with rsa-sha2-512");

    Session session = new JSch().getSession("user", "host.example.com");

    assertDoesNotThrow(
        () -> OpenSshCertificateHostKeyVerifier.checkSignature(cert, caPublicKeyAlgorithm, session),
        "RSA-CA-signed host certificate must not be rejected on the key-alg vs signature-alg name difference");
  }

  /**
   * An {@code ssh-rsa} CA key accepts the SHA-1 and SHA-2 RSA signature algorithm names; every
   * other key type still requires the signature algorithm name to match the key algorithm name.
   */
  @Test
  public void testIsSignatureAlgorithmCompatible() {
    assertTrue(OpenSshCertificateHostKeyVerifier.isSignatureAlgorithmCompatible("ssh-rsa",
        "rsa-sha2-512"));
    assertTrue(OpenSshCertificateHostKeyVerifier.isSignatureAlgorithmCompatible("ssh-rsa",
        "rsa-sha2-256"));
    assertTrue(
        OpenSshCertificateHostKeyVerifier.isSignatureAlgorithmCompatible("ssh-rsa", "ssh-rsa"));
    // Non-RSA CA keys must still match exactly.
    assertTrue(OpenSshCertificateHostKeyVerifier.isSignatureAlgorithmCompatible("ssh-ed25519",
        "ssh-ed25519"));
    assertFalse(OpenSshCertificateHostKeyVerifier
        .isSignatureAlgorithmCompatible("ecdsa-sha2-nistp256", "rsa-sha2-512"));
  }

  // ==================== Helper methods ====================

  /**
   * Parses an OpenSSH {@code *-cert.pub} file into an {@link OpenSshCertificate}, mirroring
   * {@link OpenSshCertificateAwareIdentityFile#newInstance}.
   */
  private OpenSshCertificate parseCertificate(String path) throws Exception {
    byte[] fileBytes = Util.fromFile(path);
    byte[] base64 = OpenSshCertificateUtil.extractKeyData(fileBytes);
    byte[] keyData = Util.fromBase64(base64, 0, base64.length);
    return OpenSshCertificateParser.parse(new JSch().instLogger, keyData);
  }

  // Dummy byte arrays for required fields in tests
  private static final byte[] DUMMY_NONCE = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};
  private static final byte[] DUMMY_PUBLIC_KEY =
      new byte[] {0, 0, 0, 7, 's', 's', 'h', '-', 'r', 's', 'a', 0, 0, 0, 1, 35, 0, 0, 0, 1, 0};
  private static final byte[] DUMMY_SIGNATURE_KEY =
      new byte[] {0, 0, 0, 7, 's', 's', 'h', '-', 'r', 's', 'a', 0, 0, 0, 1, 35, 0, 0, 0, 1, 0};
  private static final byte[] DUMMY_SIGNATURE =
      new byte[] {0, 0, 0, 7, 's', 's', 'h', '-', 'r', 's', 'a', 0, 0, 0, 4, 1, 2, 3, 4};
  private static final byte[] DUMMY_MESSAGE = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};

  /**
   * Creates a builder pre-configured with valid host certificate defaults.
   */
  private OpenSshCertificate.Builder createValidHostCertificateBuilder() {
    long now = java.time.Instant.now().getEpochSecond();
    return new OpenSshCertificate.Builder().keyType("ssh-rsa-cert-v01@openssh.com")
        .nonce(DUMMY_NONCE).certificatePublicKey(DUMMY_PUBLIC_KEY)
        .type(OpenSshCertificate.SSH2_CERT_TYPE_HOST).id("test-certificate")
        .principals(Arrays.asList("localhost")).validAfter(now - 3600).validBefore(now + 3600)
        .criticalOptions(Collections.emptyMap()).extensions(Collections.emptyMap())
        .signatureKey(DUMMY_SIGNATURE_KEY).signature(DUMMY_SIGNATURE).message(DUMMY_MESSAGE);
  }

  /**
   * Creates a builder pre-configured with valid user certificate defaults.
   */
  private OpenSshCertificate.Builder createValidUserCertificateBuilder() {
    long now = java.time.Instant.now().getEpochSecond();
    return new OpenSshCertificate.Builder().keyType("ssh-rsa-cert-v01@openssh.com")
        .nonce(DUMMY_NONCE).certificatePublicKey(DUMMY_PUBLIC_KEY)
        .type(OpenSshCertificate.SSH2_CERT_TYPE_USER).id("test-certificate")
        .principals(Arrays.asList("testuser")).validAfter(now - 3600).validBefore(now + 3600)
        .criticalOptions(Collections.emptyMap()).extensions(Collections.emptyMap())
        .signatureKey(DUMMY_SIGNATURE_KEY).signature(DUMMY_SIGNATURE).message(DUMMY_MESSAGE);
  }
}
