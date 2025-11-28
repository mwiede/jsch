package com.jcraft.jsch;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

public class OpenSshCertificateAwareIdentityFileTest {

  @Test
  public void testIsOpenSshCertificate_File_nullInput() {
    assertFalse(OpenSshCertificateAwareIdentityFile.isOpenSshCertificateFile(null));
  }

  @Test
  public void testIsOpenSshCertificate_File_emptyInput() {
    byte[] empty = new byte[0];
    assertFalse(OpenSshCertificateAwareIdentityFile.isOpenSshCertificateFile(empty));
  }

  @Test
  public void testIsOpenSshCertificate_sshRsaCertFile() {
    String certType = "ssh-rsa-cert-v01@openssh.com";
    byte[] input = certType.getBytes(StandardCharsets.UTF_8);
    assertTrue(OpenSshCertificateAwareIdentityFile.isOpenSshCertificateFile(input));
  }

  @Test
  public void testIsOpenSshCertificate_sshRsaCertWithDataFile() {
    String certLine = "ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20=";
    byte[] input = certLine.getBytes(StandardCharsets.UTF_8);
    assertTrue(OpenSshCertificateAwareIdentityFile.isOpenSshCertificateFile(input));
  }

  @Test
  public void testIsOpenSshCertificate_sshRsaCertWithDataAndCommentFile() {
    String certLine =
        "ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20= user@host";
    byte[] input = certLine.getBytes(StandardCharsets.UTF_8);
    assertTrue(OpenSshCertificateAwareIdentityFile.isOpenSshCertificateFile(input));
  }

  @Test
  public void testIsOpenSshCertificate_sshDssCertFile() {
    String certType = "ssh-dss-cert-v01@openssh.com";
    byte[] input = certType.getBytes(StandardCharsets.UTF_8);
    assertTrue(OpenSshCertificateAwareIdentityFile.isOpenSshCertificateFile(input));
  }

  @Test
  public void testIsOpenSshCertificate_sshDssCertWithDataFile() {
    String certLine =
        "ssh-dss-cert-v01@openssh.com AAAAHHNzaC1kc3MtY2VydC12MDFAb3BlbnNzaC5jb20= user@host";
    byte[] input = certLine.getBytes(StandardCharsets.UTF_8);
    assertTrue(OpenSshCertificateAwareIdentityFile.isOpenSshCertificateFile(input));
  }

  @Test
  public void testIsOpenSshCertificate_File_ecdsaSha2Nistp256Cert() {
    String certType = "ecdsa-sha2-nistp256-cert-v01@openssh.com";
    byte[] input = certType.getBytes(StandardCharsets.UTF_8);
    assertTrue(OpenSshCertificateAwareIdentityFile.isOpenSshCertificateFile(input));
  }

  @Test
  public void testIsOpenSshCertificate_File_ecdsaSha2Nistp256CertWithData() {
    String certLine =
        "ecdsa-sha2-nistp256-cert-v01@openssh.com AAAAKGVjZHNhLXNoYTItbmlzdHAyNTYtY2VydC12MDFAb3BlbnNzaC5jb20= user@host";
    byte[] input = certLine.getBytes(StandardCharsets.UTF_8);
    assertTrue(OpenSshCertificateAwareIdentityFile.isOpenSshCertificateFile(input));
  }

  @Test
  public void testIsOpenSshCertificate_File_ecdsaSha2Nistp384Cert() {
    String certType = "ecdsa-sha2-nistp384-cert-v01@openssh.com";
    byte[] input = certType.getBytes(StandardCharsets.UTF_8);
    assertTrue(OpenSshCertificateAwareIdentityFile.isOpenSshCertificateFile(input));
  }

  @Test
  public void testIsOpenSshCertificate_File_ecdsaSha2Nistp384CertWithData() {
    String certLine =
        "ecdsa-sha2-nistp384-cert-v01@openssh.com AAAAKGVjZHNhLXNoYTItbmlzdHAzODQtY2VydC12MDFAb3BlbnNzaC5jb20= user@host";
    byte[] input = certLine.getBytes(StandardCharsets.UTF_8);
    assertTrue(OpenSshCertificateAwareIdentityFile.isOpenSshCertificateFile(input));
  }

  @Test
  public void testIsOpenSshCertificate_File_ecdsaSha2Nistp521Cert() {
    String certType = "ecdsa-sha2-nistp521-cert-v01@openssh.com";
    byte[] input = certType.getBytes(StandardCharsets.UTF_8);
    assertTrue(OpenSshCertificateAwareIdentityFile.isOpenSshCertificateFile(input));
  }

  @Test
  public void testIsOpenSshCertificate_File_ecdsaSha2Nistp521CertWithData() {
    String certLine =
        "ecdsa-sha2-nistp521-cert-v01@openssh.com AAAAKGVjZHNhLXNoYTItbmlzdHA1MjEtY2VydC12MDFAb3BlbnNzaC5jb20= user@host";
    byte[] input = certLine.getBytes(StandardCharsets.UTF_8);
    assertTrue(OpenSshCertificateAwareIdentityFile.isOpenSshCertificateFile(input));
  }

  @Test
  public void testIsOpenSshCertificate_sshEd25519CertFile() {
    String certType = "ssh-ed25519-cert-v01@openssh.com";
    byte[] input = certType.getBytes(StandardCharsets.UTF_8);
    assertTrue(OpenSshCertificateAwareIdentityFile.isOpenSshCertificateFile(input));
  }

  @Test
  public void testIsOpenSshCertificate_sshEd25519CertWithDataFile() {
    String certLine =
        "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29t user@host";
    byte[] input = certLine.getBytes(StandardCharsets.UTF_8);
    assertTrue(OpenSshCertificateAwareIdentityFile.isOpenSshCertificateFile(input));
  }

  @Test
  public void testIsOpenSshCertificate_sshEd448CertFile() {
    String certType = "ssh-ed448-cert-v01@openssh.com";
    byte[] input = certType.getBytes(StandardCharsets.UTF_8);
    assertTrue(OpenSshCertificateAwareIdentityFile.isOpenSshCertificateFile(input));
  }

  @Test
  public void testIsOpenSshCertificate_sshEd448CertWithDataFile() {
    String certLine =
        "ssh-ed448-cert-v01@openssh.com AAAAHnNzaC1lZDQ0OC1jZXJ0LXYwMUBvcGVuc3NoLmNvbQ== user@host";
    byte[] input = certLine.getBytes(StandardCharsets.UTF_8);
    assertTrue(OpenSshCertificateAwareIdentityFile.isOpenSshCertificateFile(input));
  }

  @Test
  public void testIsOpenSshCertificate_regularSshRsaKeyFile() {
    String keyType = "ssh-rsa";
    byte[] input = keyType.getBytes(StandardCharsets.UTF_8);
    assertFalse(OpenSshCertificateAwareIdentityFile.isOpenSshCertificateFile(input));
  }

  @Test
  public void testIsOpenSshCertificate_regularSshRsaKeyWithDataFile() {
    String keyLine = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC= user@host";
    byte[] input = keyLine.getBytes(StandardCharsets.UTF_8);
    assertFalse(OpenSshCertificateAwareIdentityFile.isOpenSshCertificateFile(input));
  }

  @Test
  public void testIsOpenSshCertificate_regularSshDssKeyFile() {
    String keyType = "ssh-dss";
    byte[] input = keyType.getBytes(StandardCharsets.UTF_8);
    assertFalse(OpenSshCertificateAwareIdentityFile.isOpenSshCertificateFile(input));
  }

  @Test
  public void testIsOpenSshCertificate_File_regularEcdsaKey() {
    String keyType = "ecdsa-sha2-nistp256";
    byte[] input = keyType.getBytes(StandardCharsets.UTF_8);
    assertFalse(OpenSshCertificateAwareIdentityFile.isOpenSshCertificateFile(input));
  }

  @Test
  public void testIsOpenSshCertificate_File_regularEd25519Key() {
    String keyType = "ssh-ed25519";
    byte[] input = keyType.getBytes(StandardCharsets.UTF_8);
    assertFalse(OpenSshCertificateAwareIdentityFile.isOpenSshCertificateFile(input));
  }

  @Test
  public void testIsOpenSshCertificate_File_tooShort() {
    String tooShort = "short";
    byte[] input = tooShort.getBytes(StandardCharsets.UTF_8);
    assertFalse(OpenSshCertificateAwareIdentityFile.isOpenSshCertificateFile(input));
  }

  @Test
  public void testIsOpenSshCertificate_File_wrongSuffix() {
    String wrongSuffix = "ssh-rsa-cert-v02@openssh.com";
    byte[] input = wrongSuffix.getBytes(StandardCharsets.UTF_8);
    assertFalse(OpenSshCertificateAwareIdentityFile.isOpenSshCertificateFile(input));
  }

  @Test
  public void testIsOpenSshCertificate_File_wrongPrefix() {
    String wrongPrefix = "ssh-abc-cert-v01@openssh.com";
    byte[] input = wrongPrefix.getBytes(StandardCharsets.UTF_8);
    assertFalse(OpenSshCertificateAwareIdentityFile.isOpenSshCertificateFile(input));
  }

  @Test
  public void testIsOpenSshCertificate_File_invalidAlgorithm() {
    String invalid = "invalid-cert-v01@openssh.com";
    byte[] input = invalid.getBytes(StandardCharsets.UTF_8);
    assertFalse(OpenSshCertificateAwareIdentityFile.isOpenSshCertificateFile(input));
  }

  @Test
  public void testIsOpenSshCertificate_File_onlyWhitespace() {
    String whitespace = "   \t\n";
    byte[] input = whitespace.getBytes(StandardCharsets.UTF_8);
    assertFalse(OpenSshCertificateAwareIdentityFile.isOpenSshCertificateFile(input));
  }

  @Test
  public void testIsOpenSshCertificate_File_leadingWhitespace() {
    String certLine =
        "   ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20=";
    byte[] input = certLine.getBytes(StandardCharsets.UTF_8);
    assertTrue(OpenSshCertificateAwareIdentityFile.isOpenSshCertificateFile(input));
  }

  @Test
  public void testIsOpenSshCertificate_File_tabDelimiter() {
    String certLine = "ssh-rsa-cert-v01@openssh.com\tAAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20=";
    byte[] input = certLine.getBytes(StandardCharsets.UTF_8);
    assertTrue(OpenSshCertificateAwareIdentityFile.isOpenSshCertificateFile(input));
  }

  @Test
  public void testIsOpenSshCertificate_File_newlineDelimiter() {
    String certLine = "ssh-rsa-cert-v01@openssh.com\nAAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20=";
    byte[] input = certLine.getBytes(StandardCharsets.UTF_8);
    assertTrue(OpenSshCertificateAwareIdentityFile.isOpenSshCertificateFile(input));
  }

  @Test
  public void testIsOpenSshCertificate_File_carriageReturnDelimiter() {
    String certLine = "ssh-rsa-cert-v01@openssh.com\rAAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20=";
    byte[] input = certLine.getBytes(StandardCharsets.UTF_8);
    assertTrue(OpenSshCertificateAwareIdentityFile.isOpenSshCertificateFile(input));
  }

  @Test
  public void testIsOpenSshCertificate_File_partialMatch() {
    String partial = "ssh-rsa-cert-v01@openssh.co";
    byte[] input = partial.getBytes(StandardCharsets.UTF_8);
    assertFalse(OpenSshCertificateAwareIdentityFile.isOpenSshCertificateFile(input));
  }

  @Test
  public void testIsOpenSshCertificate_File_extraCharactersInType() {
    String extra = "ssh-rsax-cert-v01@openssh.com";
    byte[] input = extra.getBytes(StandardCharsets.UTF_8);
    assertFalse(OpenSshCertificateAwareIdentityFile.isOpenSshCertificateFile(input));
  }

  @Test
  public void testIsOpenSshCertificate_File_casesensitive() {
    String uppercase = "SSH-RSA-CERT-V01@OPENSSH.COM";
    byte[] input = uppercase.getBytes(StandardCharsets.UTF_8);
    assertFalse(OpenSshCertificateAwareIdentityFile.isOpenSshCertificateFile(input),
        "Certificate type matching should be case-sensitive");
  }

  @Test
  public void testIsOpenSshCertificate_File_minimumLengthBoundary() {
    // Exactly 27 bytes - one less than minimum (28)
    char[] chars = new char[27];
    Arrays.fill(chars, 'a');
    String justUnderMinimum = new String(chars);
    byte[] input = justUnderMinimum.getBytes(StandardCharsets.UTF_8);
    assertFalse(OpenSshCertificateAwareIdentityFile.isOpenSshCertificateFile(input));
  }

  @Test
  public void testIsOpenSshCertificate_sshRsaWrongLengthFile() {
    // ssh-rsa-cert-v01@openssh.com should be exactly 28 chars
    String tooLong = "ssh-rsax-cert-v01@openssh.com";
    byte[] input = tooLong.getBytes(StandardCharsets.UTF_8);
    assertFalse(OpenSshCertificateAwareIdentityFile.isOpenSshCertificateFile(input));
  }

  @Test
  public void testIsOpenSshCertificate_File_ecdsaWrongLength() {
    // ecdsa cert types should be exactly 40 chars
    String wrongLength = "ecdsa-sha2-nistp25-cert-v01@openssh.com"; // 39 chars
    byte[] input = wrongLength.getBytes(StandardCharsets.UTF_8);
    assertFalse(OpenSshCertificateAwareIdentityFile.isOpenSshCertificateFile(input));
  }

  @Test
  public void testIsOpenSshCertificate_File_binaryData() {
    // Binary data that might accidentally contain cert-like patterns
    byte[] binary = new byte[] {0x00, 0x01, 0x02, 's', 's', 'h', '-', 'r', 's', 'a'};
    assertFalse(OpenSshCertificateAwareIdentityFile.isOpenSshCertificateFile(binary));
  }

  @Test
  public void testIsOpenSshCertificate_File_utf8Characters() {
    // Certificate type with UTF-8 characters (should fail)
    String utf8 = "ssh-rsá-cert-v01@openssh.com";
    byte[] input = utf8.getBytes(StandardCharsets.UTF_8);
    assertFalse(OpenSshCertificateAwareIdentityFile.isOpenSshCertificateFile(input));
  }

  @Test
  public void testIsOpenSshCertificate_File_multilineWithCertOnSecondLine() {
    // Simulate a file where the cert type is on the second line
    String multiline =
        "\nssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20=";
    byte[] input = multiline.getBytes(StandardCharsets.UTF_8);
    assertTrue(OpenSshCertificateAwareIdentityFile.isOpenSshCertificateFile(input));
  }

  @Test
  public void testIsOpenSshCertificate_File_onlyKeyTypeNoWhitespace() {
    // All valid cert types without any trailing data or whitespace
    String[] certTypes = {"ssh-rsa-cert-v01@openssh.com", "ssh-dss-cert-v01@openssh.com",
        "ecdsa-sha2-nistp256-cert-v01@openssh.com", "ecdsa-sha2-nistp384-cert-v01@openssh.com",
        "ecdsa-sha2-nistp521-cert-v01@openssh.com", "ssh-ed25519-cert-v01@openssh.com",
        "ssh-ed448-cert-v01@openssh.com"};

    for (String certType : certTypes) {
      byte[] input = certType.getBytes(StandardCharsets.UTF_8);
      assertTrue(OpenSshCertificateAwareIdentityFile.isOpenSshCertificateFile(input),
          "Should recognize valid certificate type: " + certType);
    }
  }
}
