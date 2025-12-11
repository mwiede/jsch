package com.jcraft.jsch;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

public class OpenSshCertificateUtilTest {

  @Test
  public void testExtractSpaceDelimitedString_nullInput() {
    assertNull(OpenSshCertificateUtil.extractSpaceDelimitedString(null, 0));
  }

  @Test
  public void testExtractSpaceDelimitedString_emptyInput() {
    byte[] empty = new byte[0];
    assertNull(OpenSshCertificateUtil.extractSpaceDelimitedString(empty, 0));
  }

  @Test
  public void testExtractSpaceDelimitedString_singleField() {
    byte[] input = "field1".getBytes(StandardCharsets.UTF_8);
    byte[] expected = "field1".getBytes(StandardCharsets.UTF_8);
    assertArrayEquals(expected, OpenSshCertificateUtil.extractSpaceDelimitedString(input, 0));
  }

  @Test
  public void testExtractSpaceDelimitedString_multipleFieldsExtractFirst() {
    byte[] input = "field1 field2 field3".getBytes(StandardCharsets.UTF_8);
    byte[] expected = "field1".getBytes(StandardCharsets.UTF_8);
    assertArrayEquals(expected, OpenSshCertificateUtil.extractSpaceDelimitedString(input, 0));
  }

  @Test
  public void testExtractSpaceDelimitedString_multipleFieldsExtractMiddle() {
    byte[] input = "field1 field2 field3".getBytes(StandardCharsets.UTF_8);
    byte[] expected = "field2".getBytes(StandardCharsets.UTF_8);
    assertArrayEquals(expected, OpenSshCertificateUtil.extractSpaceDelimitedString(input, 1));
  }

  @Test
  public void testExtractSpaceDelimitedString_multipleFieldsExtractLast() {
    byte[] input = "field1 field2 field3".getBytes(StandardCharsets.UTF_8);
    byte[] expected = "field3".getBytes(StandardCharsets.UTF_8);
    assertArrayEquals(expected, OpenSshCertificateUtil.extractSpaceDelimitedString(input, 2));
  }

  @Test
  public void testExtractSpaceDelimitedString_indexOutOfBounds() {
    byte[] input = "field1 field2".getBytes(StandardCharsets.UTF_8);
    assertNull(OpenSshCertificateUtil.extractSpaceDelimitedString(input, 5));
  }

  @Test
  public void testExtractSpaceDelimitedString_negativeIndex() {
    byte[] input = "field1 field2".getBytes(StandardCharsets.UTF_8);
    assertNull(OpenSshCertificateUtil.extractSpaceDelimitedString(input, -1));
  }

  @Test
  public void testExtractSpaceDelimitedString_leadingWhitespace() {
    byte[] input = "   field1 field2".getBytes(StandardCharsets.UTF_8);
    byte[] expected = "field1".getBytes(StandardCharsets.UTF_8);
    assertArrayEquals(expected, OpenSshCertificateUtil.extractSpaceDelimitedString(input, 0));
  }

  @Test
  public void testExtractSpaceDelimitedString_trailingWhitespace() {
    byte[] input = "field1 field2   ".getBytes(StandardCharsets.UTF_8);
    byte[] expected = "field2".getBytes(StandardCharsets.UTF_8);
    assertArrayEquals(expected, OpenSshCertificateUtil.extractSpaceDelimitedString(input, 1));
  }

  @Test
  public void testExtractSpaceDelimitedString_multipleSpaces() {
    byte[] input = "field1    field2   field3".getBytes(StandardCharsets.UTF_8);
    byte[] expected = "field2".getBytes(StandardCharsets.UTF_8);
    assertArrayEquals(expected, OpenSshCertificateUtil.extractSpaceDelimitedString(input, 1));
  }

  @Test
  public void testExtractSpaceDelimitedString_tabDelimiter() {
    byte[] input = "field1\tfield2\tfield3".getBytes(StandardCharsets.UTF_8);
    byte[] expected = "field2".getBytes(StandardCharsets.UTF_8);
    assertArrayEquals(expected, OpenSshCertificateUtil.extractSpaceDelimitedString(input, 1));
  }

  @Test
  public void testExtractSpaceDelimitedString_mixedWhitespace() {
    byte[] input = "field1 \t  field2\t \tfield3".getBytes(StandardCharsets.UTF_8);
    byte[] expected = "field2".getBytes(StandardCharsets.UTF_8);
    assertArrayEquals(expected, OpenSshCertificateUtil.extractSpaceDelimitedString(input, 1));
  }

  @Test
  public void testExtractSpaceDelimitedString_newlineDelimiter() {
    byte[] input = "field1\nfield2\nfield3".getBytes(StandardCharsets.UTF_8);
    byte[] expected = "field2".getBytes(StandardCharsets.UTF_8);
    assertArrayEquals(expected, OpenSshCertificateUtil.extractSpaceDelimitedString(input, 1));
  }

  @Test
  public void testExtractSpaceDelimitedString_carriageReturnDelimiter() {
    byte[] input = "field1\rfield2\rfield3".getBytes(StandardCharsets.UTF_8);
    byte[] expected = "field2".getBytes(StandardCharsets.UTF_8);
    assertArrayEquals(expected, OpenSshCertificateUtil.extractSpaceDelimitedString(input, 1));
  }

  @Test
  public void testExtractSpaceDelimitedString_mixedLineEndings() {
    byte[] input = "field1\r\nfield2\n\rfield3".getBytes(StandardCharsets.UTF_8);
    byte[] expected = "field2".getBytes(StandardCharsets.UTF_8);
    assertArrayEquals(expected, OpenSshCertificateUtil.extractSpaceDelimitedString(input, 1));
  }

  @Test
  public void testExtractSpaceDelimitedString_onlyWhitespace() {
    byte[] input = "   \t\n\r   ".getBytes(StandardCharsets.UTF_8);
    assertNull(OpenSshCertificateUtil.extractSpaceDelimitedString(input, 0));
  }

  @Test
  public void testExtractSpaceDelimitedString_singleFieldWithWhitespace() {
    byte[] input = "  \t field1 \n\r ".getBytes(StandardCharsets.UTF_8);
    byte[] expected = "field1".getBytes(StandardCharsets.UTF_8);
    assertArrayEquals(expected, OpenSshCertificateUtil.extractSpaceDelimitedString(input, 0));
  }

  @Test
  public void testExtractSpaceDelimitedString_realWorldCertificate() {
    // Simulating a typical OpenSSH certificate line format
    String certLine =
        "ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20= user@host";
    byte[] input = certLine.getBytes(StandardCharsets.UTF_8);

    byte[] expectedKeyType = "ssh-rsa-cert-v01@openssh.com".getBytes(StandardCharsets.UTF_8);
    byte[] expectedKeyData =
        "AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20=".getBytes(StandardCharsets.UTF_8);
    byte[] expectedComment = "user@host".getBytes(StandardCharsets.UTF_8);

    assertArrayEquals(expectedKeyType,
        OpenSshCertificateUtil.extractSpaceDelimitedString(input, 0));
    assertArrayEquals(expectedKeyData,
        OpenSshCertificateUtil.extractSpaceDelimitedString(input, 1));
    assertArrayEquals(expectedComment,
        OpenSshCertificateUtil.extractSpaceDelimitedString(input, 2));
  }


  @Test
  public void testExtractSpaceDelimitedString_lastFieldNoTrailingWhitespace() {
    byte[] input = "field1 field2".getBytes(StandardCharsets.UTF_8);
    byte[] expected = "field2".getBytes(StandardCharsets.UTF_8);
    assertArrayEquals(expected, OpenSshCertificateUtil.extractSpaceDelimitedString(input, 1));
  }

  @Test
  public void testExtractSpaceDelimitedString_twoFields() {
    byte[] input = "key data".getBytes(StandardCharsets.UTF_8);
    byte[] expectedFirst = "key".getBytes(StandardCharsets.UTF_8);
    byte[] expectedSecond = "data".getBytes(StandardCharsets.UTF_8);

    assertArrayEquals(expectedFirst, OpenSshCertificateUtil.extractSpaceDelimitedString(input, 0));
    assertArrayEquals(expectedSecond, OpenSshCertificateUtil.extractSpaceDelimitedString(input, 1));
    assertNull(OpenSshCertificateUtil.extractSpaceDelimitedString(input, 2));
  }

  @Test
  public void testExtractSpaceDelimitedString_specialCharactersInFields() {
    byte[] input = "field-1 field_2 field.3@domain".getBytes(StandardCharsets.UTF_8);
    byte[] expected = "field.3@domain".getBytes(StandardCharsets.UTF_8);
    assertArrayEquals(expected, OpenSshCertificateUtil.extractSpaceDelimitedString(input, 2));
  }

  // ==================== Tests for isCertificateSignedByTrustedCA ====================

  /**
   * Test that isCertificateSignedByTrustedCA returns true when a matching, non-revoked CA is found.
   */
  @Test
  public void testIsCertificateSignedByTrustedCA_trustedCAFound() throws Exception {
    // Setup
    JSch jsch = new JSch();
    KnownHosts knownHosts = new KnownHosts(jsch);
    String host = "public.example.com";
    String base64CaPublicKey = "AAAAB3NzaC1yc2EAAAADAQABAAABAQ==";

    // Create a matching CA host key
    byte[] keyBytes =
        Util.fromBase64(Util.str2byte(base64CaPublicKey), 0, base64CaPublicKey.length());
    HostKey caHostKey =
        new HostKey("@cert-authority", "*.example.com", HostKey.SSHRSA, keyBytes, null);

    knownHosts.add(caHostKey, null);

    // Execute
    boolean result =
        OpenSshCertificateUtil.isCertificateSignedByTrustedCA(knownHosts, host, base64CaPublicKey);

    // Verify
    assertTrue(result, "Should return true when trusted CA is found");
  }

  /**
   * Test that isCertificateSignedByTrustedCA returns false when the CA public key doesn't match.
   */
  @Test
  public void testIsCertificateSignedByTrustedCA_caKeyMismatch() throws Exception {
    // Setup
    JSch jsch = new JSch();
    KnownHosts knownHosts = new KnownHosts(jsch);
    String host = "example.com";
    String base64CaPublicKey = "AAAAB3NzaC1yc2EAAAADAQABAAABAQ==";
    String differentCaKey = "AAAAB3NzaC1yc2EAAAADAQABAAABDIFFERENT==";

    // Create a CA with different key
    byte[] keyBytes = Util.fromBase64(Util.str2byte(differentCaKey), 0, differentCaKey.length());
    HostKey caHostKey =
        new HostKey("@cert-authority", "*.example.com", HostKey.SSHRSA, keyBytes, null);

    knownHosts.add(caHostKey, null);

    // Execute
    boolean result =
        OpenSshCertificateUtil.isCertificateSignedByTrustedCA(knownHosts, host, base64CaPublicKey);

    // Verify
    assertFalse(result, "Should return false when CA key doesn't match");
  }

  /**
   * Test that isCertificateSignedByTrustedCA returns false when the CA is revoked.
   */
  @Test
  public void testIsCertificateSignedByTrustedCA_caIsRevoked() throws Exception {
    // Setup
    JSch jsch = new JSch();
    KnownHosts knownHosts = new KnownHosts(jsch);
    String host = "example.com";
    String base64CaPublicKey = "AAAAB3NzaC1yc2EAAAADAQABAAABAQ==";

    byte[] keyBytes =
        Util.fromBase64(Util.str2byte(base64CaPublicKey), 0, base64CaPublicKey.length());

    // Create a @cert-authority entry
    HostKey caHostKey =
        new HostKey("@cert-authority", "*.example.com", HostKey.SSHRSA, keyBytes, null);

    // Create a @revoked entry with the same key
    HostKey revokedHostKey =
        new HostKey("@revoked", "*.example.com", HostKey.SSHRSA, keyBytes, null);

    knownHosts.add(caHostKey, null);
    knownHosts.add(revokedHostKey, null);

    // Execute
    boolean result =
        OpenSshCertificateUtil.isCertificateSignedByTrustedCA(knownHosts, host, base64CaPublicKey);

    // Verify
    assertFalse(result, "Should return false when CA is revoked (fail-closed security)");
  }

  /**
   * Test that isCertificateSignedByTrustedCA returns false when host pattern doesn't match.
   */
  @Test
  public void testIsCertificateSignedByTrustedCA_hostPatternMismatch() throws Exception {
    // Setup
    JSch jsch = new JSch();
    KnownHosts knownHosts = new KnownHosts(jsch);
    String host = "different.com";
    String base64CaPublicKey = "AAAAB3NzaC1yc2EAAAADAQABAAABAQ==";

    byte[] keyBytes =
        Util.fromBase64(Util.str2byte(base64CaPublicKey), 0, base64CaPublicKey.length());
    HostKey caHostKey =
        new HostKey("@cert-authority", "*.example.com", HostKey.SSHRSA, keyBytes, null);

    knownHosts.add(caHostKey, null);

    // Execute
    boolean result =
        OpenSshCertificateUtil.isCertificateSignedByTrustedCA(knownHosts, host, base64CaPublicKey);

    // Verify
    assertFalse(result, "Should return false when host pattern doesn't match");
  }

  /**
   * Test that isCertificateSignedByTrustedCA returns false when repository is empty.
   */
  @Test
  public void testIsCertificateSignedByTrustedCA_emptyRepository() throws JSchException {
    // Setup
    JSch jsch = new JSch();
    KnownHosts knownHosts = new KnownHosts(jsch);
    String host = "example.com";
    String base64CaPublicKey = "AAAAB3NzaC1yc2EAAAADAQABAAABAQ==";

    // Execute
    boolean result =
        OpenSshCertificateUtil.isCertificateSignedByTrustedCA(knownHosts, host, base64CaPublicKey);

    // Verify
    assertFalse(result, "Should return false when repository is empty");
  }

  /**
   * Test that isCertificateSignedByTrustedCA succeeds when there are multiple CAs and one matches.
   */
  @Test
  public void testIsCertificateSignedByTrustedCA_multipleCAsOneMatches() throws Exception {
    // Setup
    JSch jsch = new JSch();
    KnownHosts knownHosts = new KnownHosts(jsch);
    String host = "this.example.com";
    String base64CaPublicKey = "AAAAB3NzaC1yc2EAAAADAQABAAABAQ==";
    String differentCaKey = "AAAAB3NzaC1yc2EAAAADAQABAAABDIFFERENT==";

    byte[] matchingKeyBytes =
        Util.fromBase64(Util.str2byte(base64CaPublicKey), 0, base64CaPublicKey.length());
    byte[] differentKeyBytes =
        Util.fromBase64(Util.str2byte(differentCaKey), 0, differentCaKey.length());

    // Create multiple CA entries - one matches, one doesn't
    HostKey caHostKey1 =
        new HostKey("@cert-authority", "*.test.com", HostKey.SSHRSA, differentKeyBytes, null);
    HostKey caHostKey2 =
        new HostKey("@cert-authority", "*.example.com", HostKey.SSHRSA, matchingKeyBytes, null);

    knownHosts.add(caHostKey1, null);
    knownHosts.add(caHostKey2, null);

    // Execute
    boolean result =
        OpenSshCertificateUtil.isCertificateSignedByTrustedCA(knownHosts, host, base64CaPublicKey);

    // Verify
    assertTrue(result, "Should return true when one of multiple CAs matches (anyMatch behavior)");
  }

  /**
   * Test that isCertificateSignedByTrustedCA ignores non-@cert-authority entries.
   */
  @Test
  public void testIsCertificateSignedByTrustedCA_ignoresNonCaEntries() throws Exception {
    // Setup
    JSch jsch = new JSch();
    KnownHosts knownHosts = new KnownHosts(jsch);
    String host = "example.com";
    String base64CaPublicKey = "AAAAB3NzaC1yc2EAAAADAQABAAABAQ==";

    byte[] keyBytes =
        Util.fromBase64(Util.str2byte(base64CaPublicKey), 0, base64CaPublicKey.length());

    // Create regular host key (no @cert-authority marker)
    HostKey regularHostKey = new HostKey("", "example.com", HostKey.SSHRSA, keyBytes, null);

    // Create @revoked entry
    HostKey revokedHostKey = new HostKey("@revoked", "example.com", HostKey.SSHRSA, keyBytes, null);

    knownHosts.add(regularHostKey, null);
    knownHosts.add(revokedHostKey, null);

    // Execute
    boolean result =
        OpenSshCertificateUtil.isCertificateSignedByTrustedCA(knownHosts, host, base64CaPublicKey);

    // Verify
    assertFalse(result, "Should ignore entries without @cert-authority marker");
  }

  /**
   * Test that isCertificateSignedByTrustedCA handles wildcard host patterns correctly.
   */
  @Test
  public void testIsCertificateSignedByTrustedCA_wildcardHostPattern() throws Exception {
    // Setup
    JSch jsch = new JSch();
    KnownHosts knownHosts = new KnownHosts(jsch);
    String host = "sub.example.com";
    String base64CaPublicKey = "AAAAB3NzaC1yc2EAAAADAQABAAABAQ==";

    byte[] keyBytes =
        Util.fromBase64(Util.str2byte(base64CaPublicKey), 0, base64CaPublicKey.length());

    // Create CA with wildcard pattern
    HostKey caHostKey =
        new HostKey("@cert-authority", "*.example.com", HostKey.SSHRSA, keyBytes, null);

    knownHosts.add(caHostKey, null);

    // Execute
    boolean result =
        OpenSshCertificateUtil.isCertificateSignedByTrustedCA(knownHosts, host, base64CaPublicKey);

    // Verify
    assertTrue(result, "Should match wildcard host pattern *.example.com with sub.example.com");
  }

  /**
   * Test that isCertificateSignedByTrustedCA handles different key types (Ed25519).
   */
  @Test
  public void testIsCertificateSignedByTrustedCA_ed25519KeyType() throws Exception {
    // Setup
    JSch jsch = new JSch();
    KnownHosts knownHosts = new KnownHosts(jsch);
    String host = "example.com";
    String base64CaPublicKey = "AAAAC3NzaC1lZDI1NTE5AAAAI==";

    byte[] keyBytes =
        Util.fromBase64(Util.str2byte(base64CaPublicKey), 0, base64CaPublicKey.length());

    HostKey caHostKey =
        new HostKey("@cert-authority", "*example.com", HostKey.ED25519, keyBytes, null);

    knownHosts.add(caHostKey, null);

    // Execute
    boolean result =
        OpenSshCertificateUtil.isCertificateSignedByTrustedCA(knownHosts, host, base64CaPublicKey);

    // Verify
    assertTrue(result, "Should work with Ed25519 key type");
  }

  /**
   * Test that isCertificateSignedByTrustedCA correctly handles the scenario where a CA exists but
   * with a null key field.
   */
  @Test
  public void testIsCertificateSignedByTrustedCA_caWithNullKey() throws Exception {
    // Setup
    JSch jsch = new JSch();
    KnownHosts knownHosts = new KnownHosts(jsch);
    String host = "example.com";
    String base64CaPublicKey = "AAAAB3NzaC1yc2EAAAADAQABAAABAQ==";

    // Create CA with null key (malformed entry)
    HostKey caHostKeyWithNullKey =
        new HostKey("@cert-authority", "*.example.com", HostKey.SSHRSA, null, null);

    knownHosts.add(caHostKeyWithNullKey, null);

    // Execute
    boolean result =
        OpenSshCertificateUtil.isCertificateSignedByTrustedCA(knownHosts, host, base64CaPublicKey);

    // Verify
    assertFalse(result, "Should return false when CA has null key (fail-closed security)");
  }

  /**
   * Test complex scenario: multiple CAs, some revoked, some with different keys, one valid match.
   */
  @Test
  public void testIsCertificateSignedByTrustedCA_complexScenario() throws Exception {
    // Setup
    JSch jsch = new JSch();
    KnownHosts knownHosts = new KnownHosts(jsch);
    String host = "prod.example.com";
    String validCaKey = "AAAAB3NzaC1yc2EVALIDKEY==";
    String revokedCaKey = "AAAAB3NzaC1yc2EREVOKEDKEY==";
    String differentCaKey = "AAAAB3NzaC1yc2EDIFFERENTKEY==";

    byte[] validKeyBytes = Util.fromBase64(Util.str2byte(validCaKey), 0, validCaKey.length());
    byte[] revokedKeyBytes = Util.fromBase64(Util.str2byte(revokedCaKey), 0, revokedCaKey.length());
    byte[] differentKeyBytes =
        Util.fromBase64(Util.str2byte(differentCaKey), 0, differentCaKey.length());

    // Create multiple entries
    HostKey validCa =
        new HostKey("@cert-authority", "*.example.com", HostKey.SSHRSA, validKeyBytes, null);
    HostKey revokedCa =
        new HostKey("@cert-authority", "*.example.com", HostKey.SSHRSA, revokedKeyBytes, null);
    HostKey revokedMarker =
        new HostKey("@revoked", "*.example.com", HostKey.SSHRSA, revokedKeyBytes, null);
    HostKey differentCa =
        new HostKey("@cert-authority", "*.test.com", HostKey.SSHRSA, differentKeyBytes, null);
    HostKey regularHost = new HostKey("", "prod.example.com", HostKey.SSHRSA, validKeyBytes, null);

    knownHosts.add(differentCa, null);
    knownHosts.add(revokedCa, null);
    knownHosts.add(revokedMarker, null);
    knownHosts.add(validCa, null);
    knownHosts.add(regularHost, null);

    // Execute
    boolean result =
        OpenSshCertificateUtil.isCertificateSignedByTrustedCA(knownHosts, host, validCaKey);

    // Verify
    assertTrue(result,
        "Should find the valid CA among multiple entries, ignoring revoked/different/null entries");
  }
}
