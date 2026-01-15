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
}
