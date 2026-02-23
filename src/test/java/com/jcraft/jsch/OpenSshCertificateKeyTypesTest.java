package com.jcraft.jsch;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Unit tests for {@link OpenSshCertificateKeyTypes}.
 */
public class OpenSshCertificateKeyTypesTest {

  // ==================== Tests for isCertificateKeyType ====================

  @ParameterizedTest
  @ValueSource(strings = {"ssh-rsa-cert-v01@openssh.com", "ssh-dss-cert-v01@openssh.com",
      "ecdsa-sha2-nistp256-cert-v01@openssh.com", "ecdsa-sha2-nistp384-cert-v01@openssh.com",
      "ecdsa-sha2-nistp521-cert-v01@openssh.com", "ssh-ed25519-cert-v01@openssh.com",
      "ssh-ed448-cert-v01@openssh.com", "rsa-sha2-256-cert-v01@openssh.com",
      "rsa-sha2-512-cert-v01@openssh.com"})
  public void testIsCertificateKeyType_validCertTypes(String keyType) {
    assertTrue(OpenSshCertificateKeyTypes.isCertificateKeyType(keyType),
        "Should recognize " + keyType + " as certificate type");
  }

  @ParameterizedTest
  @ValueSource(strings = {"ssh-rsa", "ssh-dss", "ecdsa-sha2-nistp256", "ssh-ed25519", "ssh-ed448",
      "rsa-sha2-256", "rsa-sha2-512", "unknown-cert-v01@openssh.com",
      "ssh-rsa-cert-v02@openssh.com"})
  public void testIsCertificateKeyType_nonCertTypes(String keyType) {
    assertFalse(OpenSshCertificateKeyTypes.isCertificateKeyType(keyType),
        "Should not recognize " + keyType + " as certificate type");
  }

  @Test
  public void testIsCertificateKeyType_null() {
    assertFalse(OpenSshCertificateKeyTypes.isCertificateKeyType(null),
        "Should return false for null");
  }

  // ==================== Tests for getBaseKeyType ====================

  @ParameterizedTest
  @CsvSource({"ssh-rsa-cert-v01@openssh.com,ssh-rsa", "ssh-dss-cert-v01@openssh.com,ssh-dss",
      "ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp256",
      "ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp384",
      "ecdsa-sha2-nistp521-cert-v01@openssh.com,ecdsa-sha2-nistp521",
      "ssh-ed25519-cert-v01@openssh.com,ssh-ed25519", "ssh-ed448-cert-v01@openssh.com,ssh-ed448",
      "rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256",
      "rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512"})
  public void testGetBaseKeyType_certTypes(String certType, String expectedBaseType) {
    assertEquals(expectedBaseType, OpenSshCertificateKeyTypes.getBaseKeyType(certType));
  }

  @ParameterizedTest
  @ValueSource(strings = {"ssh-rsa", "ssh-dss", "ecdsa-sha2-nistp256", "ssh-ed25519"})
  public void testGetBaseKeyType_nonCertTypes(String keyType) {
    assertEquals(keyType, OpenSshCertificateKeyTypes.getBaseKeyType(keyType),
        "Should return original key type for non-certificate types");
  }

  @Test
  public void testGetBaseKeyType_null() {
    assertNull(OpenSshCertificateKeyTypes.getBaseKeyType(null),
        "Should return null for null input");
  }

  @ParameterizedTest
  @NullAndEmptySource
  public void testGetBaseKeyType_nullOrEmpty(String keyType) {
    assertNull(OpenSshCertificateKeyTypes.getBaseKeyType(keyType),
        "Should return null for null or empty input");
  }

  @ParameterizedTest
  @ValueSource(strings = {"  ", "\t", "\n"})
  public void testGetBaseKeyType_blankReturnsOriginal(String keyType) {
    assertEquals(keyType, OpenSshCertificateKeyTypes.getBaseKeyType(keyType),
        "Should return original string for blank (non-empty) input");
  }

  // ==================== Tests for constants ====================

  @Test
  public void testConstantsHaveCorrectValues() {
    assertEquals("ssh-rsa-cert-v01@openssh.com", OpenSshCertificateKeyTypes.SSH_RSA_CERT_V01);
    assertEquals("ssh-dss-cert-v01@openssh.com", OpenSshCertificateKeyTypes.SSH_DSS_CERT_V01);
    assertEquals("ecdsa-sha2-nistp256-cert-v01@openssh.com",
        OpenSshCertificateKeyTypes.ECDSA_SHA2_NISTP256_CERT_V01);
    assertEquals("ecdsa-sha2-nistp384-cert-v01@openssh.com",
        OpenSshCertificateKeyTypes.ECDSA_SHA2_NISTP384_CERT_V01);
    assertEquals("ecdsa-sha2-nistp521-cert-v01@openssh.com",
        OpenSshCertificateKeyTypes.ECDSA_SHA2_NISTP521_CERT_V01);
    assertEquals("ssh-ed25519-cert-v01@openssh.com",
        OpenSshCertificateKeyTypes.SSH_ED25519_CERT_V01);
    assertEquals("ssh-ed448-cert-v01@openssh.com", OpenSshCertificateKeyTypes.SSH_ED448_CERT_V01);
    assertEquals("-cert-v01@openssh.com", OpenSshCertificateKeyTypes.CERT_SUFFIX);
  }

  // ==================== Tests for getCertificateKeyType ====================

  @ParameterizedTest
  @CsvSource({"ssh-rsa,ssh-rsa-cert-v01@openssh.com", "ssh-dss,ssh-dss-cert-v01@openssh.com",
      "ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com",
      "ecdsa-sha2-nistp384,ecdsa-sha2-nistp384-cert-v01@openssh.com",
      "ecdsa-sha2-nistp521,ecdsa-sha2-nistp521-cert-v01@openssh.com",
      "ssh-ed25519,ssh-ed25519-cert-v01@openssh.com", "ssh-ed448,ssh-ed448-cert-v01@openssh.com",
      "rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com",
      "rsa-sha2-512,rsa-sha2-512-cert-v01@openssh.com"})
  public void testGetCertificateKeyType_knownAlgorithms(String baseAlg, String expectedCertType) {
    assertEquals(expectedCertType, OpenSshCertificateKeyTypes.getCertificateKeyType(baseAlg));
  }

  @ParameterizedTest
  @ValueSource(strings = {"unknown-algorithm", "ssh-rsa-cert-v01@openssh.com", "aes256-ctr"})
  public void testGetCertificateKeyType_unknownAlgorithms(String algorithm) {
    assertNull(OpenSshCertificateKeyTypes.getCertificateKeyType(algorithm),
        "Should return null for unknown or already-certificate algorithms");
  }

  @Test
  public void testGetCertificateKeyType_null() {
    assertNull(OpenSshCertificateKeyTypes.getCertificateKeyType(null),
        "Should return null for null input");
  }

  @Test
  public void testGetCertificateKeyType_roundTrip() {
    // Verify that getCertificateKeyType and getBaseKeyType are inverse operations
    String[] baseAlgorithms =
        {"ssh-rsa", "ssh-dss", "ecdsa-sha2-nistp256", "ssh-ed25519", "ssh-ed448"};
    for (String base : baseAlgorithms) {
      String certType = OpenSshCertificateKeyTypes.getCertificateKeyType(base);
      assertNotNull(certType, "Certificate type should not be null for " + base);
      String recoveredBase = OpenSshCertificateKeyTypes.getBaseKeyType(certType);
      assertEquals(base, recoveredBase, "Round-trip should recover original base algorithm");
    }
  }

  // ==================== Tests for prefer_known_host_key_types normalization ====================

  /**
   * Tests the normalization chain used in Session.java for prefer_known_host_key_types. This
   * verifies that certificate algorithms are correctly normalized to match against known_hosts
   * entries, aligning with OpenSSH behavior.
   *
   * See: https://github.com/openssh/openssh-portable/blob/master/sshconnect2.c#L340
   */
  @ParameterizedTest
  @CsvSource({
      // RSA certificate variants should all normalize to ssh-rsa for matching
      "ssh-rsa-cert-v01@openssh.com,ssh-rsa", "rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256", // First
                                                                                                // step
      "rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512", // First step
      // Other certificate types normalize to their base types
      "ssh-dss-cert-v01@openssh.com,ssh-dss",
      "ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp256",
      "ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp384",
      "ecdsa-sha2-nistp521-cert-v01@openssh.com,ecdsa-sha2-nistp521",
      "ssh-ed25519-cert-v01@openssh.com,ssh-ed25519", "ssh-ed448-cert-v01@openssh.com,ssh-ed448",
      // Non-certificate types should return themselves
      "ssh-rsa,ssh-rsa", "rsa-sha2-256,rsa-sha2-256", "rsa-sha2-512,rsa-sha2-512",
      "ssh-ed25519,ssh-ed25519", "ecdsa-sha2-nistp256,ecdsa-sha2-nistp256"})
  public void testNormalizationForKnownHostMatching(String algorithm, String expectedNormalized) {
    // This simulates the normalization logic in Session.java
    String type = algorithm;
    String baseType = OpenSshCertificateKeyTypes.getBaseKeyType(type);
    if (baseType != null && !baseType.equals(type)) {
      type = baseType;
    }
    assertEquals(expectedNormalized, type, "Algorithm " + algorithm + " should normalize to "
        + expectedNormalized + " for known_hosts matching");
  }

  /**
   * Tests the complete normalization chain including RSA signature variant normalization. This
   * simulates the full logic in Session.java where RSA variants are further normalized to ssh-rsa.
   */
  @ParameterizedTest
  @CsvSource({
      // All RSA certificate variants should ultimately normalize to ssh-rsa
      "ssh-rsa-cert-v01@openssh.com,ssh-rsa", "rsa-sha2-256-cert-v01@openssh.com,ssh-rsa", // cert
                                                                                           // ->
                                                                                           // rsa-sha2-256
                                                                                           // ->
                                                                                           // ssh-rsa
      "rsa-sha2-512-cert-v01@openssh.com,ssh-rsa", // cert -> rsa-sha2-512 -> ssh-rsa
      // RSA signature variants normalize to ssh-rsa
      "rsa-sha2-256,ssh-rsa", "rsa-sha2-512,ssh-rsa", "ssh-rsa,ssh-rsa",
      // Other types remain unchanged
      "ssh-ed25519-cert-v01@openssh.com,ssh-ed25519", "ssh-ed25519,ssh-ed25519",
      "ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp256",
      "ecdsa-sha2-nistp256,ecdsa-sha2-nistp256"})
  public void testCompleteNormalizationChain(String algorithm, String expectedFinalType) {
    // Simulate the complete normalization chain from Session.java
    String type = algorithm;

    // Step 1: Normalize certificate to base type
    String baseType = OpenSshCertificateKeyTypes.getBaseKeyType(type);
    if (baseType != null && !baseType.equals(type)) {
      type = baseType;
    }

    // Step 2: Normalize RSA signature variants to ssh-rsa
    // (This matches the logic in Session.java lines 849-853 and 863-865)
    if (type.equals("rsa-sha2-256") || type.equals("rsa-sha2-512")) {
      type = "ssh-rsa";
    }

    assertEquals(expectedFinalType, type,
        "Algorithm " + algorithm + " should ultimately normalize to " + expectedFinalType);
  }

  /**
   * Tests a realistic scenario: when a user has ssh-rsa in known_hosts, all RSA-based certificate
   * algorithms should match against it.
   */
  @Test
  public void testRsaCertificateMatchingAgainstKnownHosts() {
    String knownHostKeyType = "ssh-rsa";

    String[] rsaCertAlgorithms =
        {"ssh-rsa-cert-v01@openssh.com", "rsa-sha2-256-cert-v01@openssh.com",
            "rsa-sha2-512-cert-v01@openssh.com", "rsa-sha2-256", "rsa-sha2-512", "ssh-rsa"};

    for (String algo : rsaCertAlgorithms) {
      // Simulate normalization
      String type = algo;
      String baseType = OpenSshCertificateKeyTypes.getBaseKeyType(type);
      if (baseType != null && !baseType.equals(type)) {
        type = baseType;
      }
      if (type.equals("rsa-sha2-256") || type.equals("rsa-sha2-512")) {
        type = "ssh-rsa";
      }

      assertEquals(knownHostKeyType, type,
          "Algorithm " + algo + " should match against " + knownHostKeyType + " in known_hosts");
    }
  }

  /**
   * Tests that non-RSA certificate algorithms only match their own base type.
   */
  @Test
  public void testNonRsaCertificateMatching() {
    // Ed25519 certificates should only match ed25519
    String ed25519Cert = "ssh-ed25519-cert-v01@openssh.com";
    String baseType = OpenSshCertificateKeyTypes.getBaseKeyType(ed25519Cert);
    assertEquals("ssh-ed25519", baseType, "Ed25519 certificate should normalize to ssh-ed25519");

    // ECDSA certificates should only match their specific curve
    String ecdsaCert = "ecdsa-sha2-nistp256-cert-v01@openssh.com";
    baseType = OpenSshCertificateKeyTypes.getBaseKeyType(ecdsaCert);
    assertEquals("ecdsa-sha2-nistp256", baseType,
        "ECDSA-256 certificate should normalize to ecdsa-sha2-nistp256");
  }
}
