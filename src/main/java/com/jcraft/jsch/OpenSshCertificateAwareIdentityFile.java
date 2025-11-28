package com.jcraft.jsch;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * An {@link Identity} implementation that supports OpenSSH certificates.
 *
 * <p>
 * This class handles SSH identity files that contain OpenSSH certificates, which combine a public
 * key with additional metadata and restrictions signed by a certificate authority. It supports all
 * standard OpenSSH certificate types including RSA, DSA, ECDSA, and Ed25519.
 * </p>
 *
 * <p>
 * The class can load certificates from file pairs (private key file + certificate file) and
 * provides all the functionality needed for SSH authentication using certificates.
 * </p>
 */
class OpenSshCertificateAwareIdentityFile implements Identity {

  static final String SSH_RSA_CERT_V01_AT_OPENSSH_DOT_COM = "ssh-rsa-cert-v01@openssh.com";

  static final String SSH_DSS_CERT_V01_AT_OPENSSH_DOT_COM = "ssh-dss-cert-v01@openssh.com";

  static final String ECDSA_SHA2_NISTP256_CERT_V01_AT_OPENSSH_DOT_COM =
      "ecdsa-sha2-nistp256-cert-v01@openssh.com";

  static final String ECDSA_SHA2_NISTP384_CERT_V01_AT_OPENSSH_DOT_COM =
      "ecdsa-sha2-nistp384-cert-v01@openssh.com";

  static final String ECDSA_SHA2_NISTP521_CERT_V01_AT_OPENSSH_DOT_COM =
      "ecdsa-sha2-nistp521-cert-v01@openssh.com";

  static final String SSH_ED25519_CERT_V01_AT_OPENSSH_DOT_COM = "ssh-ed25519-cert-v01@openssh.com";

  static final String SSH_ED448_CERT_V01_AT_OPENSSH_DOT_COM = "ssh-ed448-cert-v01@openssh.com";

  /**
   * parsed certificate.
   **/
  private final OpenSshCertificate certificate;

  /**
   * the key type declared in the first part of the file
   **/
  private final String keyType;

  /**
   * The entire certificate as raw bytes
   */
  private final byte[] publicKeyBlob;

  /**
   * The key pair containing the private key
   */
  private final KeyPair kpair;

  /**
   * The identity name/path
   */
  private final String identity;

  /**
   * Optional comment associated with the identity
   */
  private final String comment;

  /**
   * Determines if the given certificate file content as byte array, represents an OpenSSH
   * certificate.
   *
   * @param certificateFileContent the certificate bytes to check
   * @return {@code true} if the file content is a supported OpenSSH certificate type, {@code false}
   *         otherwise
   */
  static boolean isOpenSshCertificateFile(byte[] certificateFileContent) {
    if (certificateFileContent == null || certificateFileContent.length == 0) {
      return false;
    }

    byte[] keyTypeBytes =
        OpenSshCertificateUtil.extractSpaceDelimitedString(certificateFileContent, 0);

    // avoid converting byte array to string if the keyType is clearly not a supported certificate
    if (keyTypeBytes == null || keyTypeBytes.length == 0 || keyTypeBytes.length > 100) {
      return false;
    }

    String keyType = new String(keyTypeBytes, StandardCharsets.UTF_8);

    return isOpenSshCertificateKeyType(keyType);

    /*
     * switch(keyType){ case SSH_RSA_CERT_V01_AT_OPENSSH_DOT_COM: case
     * SSH_DSS_CERT_V01_AT_OPENSSH_DOT_COM: case ECDSA_SHA2_NISTP256_CERT_V01_AT_OPENSSH_DOT_COM:
     * case ECDSA_SHA2_NISTP384_CERT_V01_AT_OPENSSH_DOT_COM: case
     * ECDSA_SHA2_NISTP521_CERT_V01_AT_OPENSSH_DOT_COM: case
     * SSH_ED25519_CERT_V01_AT_OPENSSH_DOT_COM: case SSH_ED448_CERT_V01_AT_OPENSSH_DOT_COM: return
     * true; default: return false; }
     */
  }



  /**
   * Determines if the given key type represents an OpenSSH certificate.
   *
   * @param publicKeyType the key type string to check
   * @return {@code true} if the type is a supported OpenSSH certificate type, {@code false}
   *         otherwise
   */
  static boolean isOpenSshCertificateKeyType(String publicKeyType) {
    switch (publicKeyType) {
      case SSH_RSA_CERT_V01_AT_OPENSSH_DOT_COM:
      case SSH_DSS_CERT_V01_AT_OPENSSH_DOT_COM:
      case ECDSA_SHA2_NISTP256_CERT_V01_AT_OPENSSH_DOT_COM:
      case ECDSA_SHA2_NISTP384_CERT_V01_AT_OPENSSH_DOT_COM:
      case ECDSA_SHA2_NISTP521_CERT_V01_AT_OPENSSH_DOT_COM:
      case SSH_ED25519_CERT_V01_AT_OPENSSH_DOT_COM:
      case SSH_ED448_CERT_V01_AT_OPENSSH_DOT_COM:
        return true;
      default:
        return false;
    }
  }

  /**
   * Creates a new certificate-aware identity from file paths.
   *
   * @param prvfile path to the private key file
   * @param pubfile path to the certificate file
   * @param instLogger logger instance for debugging
   * @return a new Identity instance
   * @throws JSchException if the files cannot be loaded or parsed
   */
  static Identity newInstance(String prvfile, String pubfile, JSch.InstanceLogger instLogger)
      throws JSchException {
    byte[] prvkey;
    byte[] certificateFileContent;

    try {
      prvkey = Util.fromFile(prvfile);
      certificateFileContent = Util.fromFile(pubfile);
    } catch (IOException e) {
      throw new JSchException(e.toString(), e);
    }
    return newInstance(prvfile, prvkey, certificateFileContent, instLogger);
  }

  /**
   * Creates a new certificate-aware identity from byte arrays.
   *
   * @param name the identity name
   * @param prvkey the private key bytes
   * @param certificateFileContentBytes the certificate bytes
   * @param instLogger logger instance for debugging
   * @return a new Identity instance
   * @throws JSchException if the certificate cannot be parsed
   */
  static Identity newInstance(String name, byte[] prvkey, byte[] certificateFileContentBytes,
      JSch.InstanceLogger instLogger) throws JSchException {
    OpenSshCertificate cert;
    byte[] certPublicKey;
    KeyPair kpair;
    byte[] declaredKeyTypeBytes;
    byte[] commentBytes;
    byte[] base64KeyDataBytes;
    String declaredKeyType;
    String comment;

    try {
      declaredKeyTypeBytes = OpenSshCertificateUtil.extractKeyType(certificateFileContentBytes);
      base64KeyDataBytes = OpenSshCertificateUtil.extractKeyData(certificateFileContentBytes);
      commentBytes = OpenSshCertificateUtil.extractComment(certificateFileContentBytes);
      byte[] keyData = Util.fromBase64(base64KeyDataBytes, 0, base64KeyDataBytes.length);
      cert = OpenSshCertificateParser.parse(instLogger, keyData);

      declaredKeyType = Util.byte2str(declaredKeyTypeBytes, StandardCharsets.UTF_8);
      comment = Util.byte2str(commentBytes, StandardCharsets.UTF_8);

      // keyType
      if (OpenSshCertificateUtil.isEmpty(cert.getKeyType())
          || !cert.getKeyType().equals(declaredKeyType)) {
        instLogger.getLogger().log(Logger.WARN,
            "Key type declared at the beginning of the certificate file, does not correspond to the encoded key type. Declared type: '"
                + declaredKeyType + "' - Encoded Key type: '" + cert.getKeyType() + "'");
      }

      if (!cert.isValidNow()) {
        instLogger.getLogger().log(Logger.WARN,
            "certificate is not valid. Valid after: "
                + OpenSshCertificateUtil.toDateString(cert.getValidAfter()) + " - Valid before: "
                + OpenSshCertificateUtil.toDateString(cert.getValidBefore()));
      }

      certPublicKey = cert.getCertificatePublicKey();
      kpair = KeyPair.load(instLogger, prvkey, certPublicKey);

    } catch (Exception e) {
      throw new JSchException(e.toString(), e);
    }
    return new OpenSshCertificateAwareIdentityFile(name, declaredKeyType, base64KeyDataBytes, cert,
        kpair, comment);
  }

  /**
   * Private constructor for creating certificate-aware identity instances.
   *
   * @param name the identity name
   * @param keyType the key type declared in the certificate file
   * @param certificate the parsed certificate
   * @param kpair the key pair containing the private key
   * @param comment the optional comment from the certificate file
   */
  private OpenSshCertificateAwareIdentityFile(String name, String keyType, byte[] base64KeyData,
      OpenSshCertificate certificate, KeyPair kpair, String comment) throws JSchException {
    this.identity = name;
    this.certificate = certificate;
    this.kpair = kpair;
    this.comment = comment;
    this.keyType = keyType;
    this.publicKeyBlob = Util.fromBase64(base64KeyData, 0, base64KeyData.length);
  }

  @Override
  public boolean setPassphrase(byte[] passphrase) {
    return kpair.decrypt(passphrase);
  }

  @Override
  public byte[] getPublicKeyBlob() {
    return publicKeyBlob;
  }

  @Override
  public byte[] getSignature(byte[] data) {
    return kpair.getSignature(data);
  }

  @Override
  public byte[] getSignature(byte[] data, String alg) {
    String rawKeyType = OpenSshCertificateUtil.getRawKeyType(keyType);
    return kpair.getSignature(data, rawKeyType);
  }

  @Override
  public String getAlgName() {
    return certificate.getKeyType();
  }

  @Override
  public String getName() {
    return identity;
  }

  @Override
  public boolean isEncrypted() {
    return kpair.isEncrypted();
  }

  @Override
  public void clear() {
    kpair.dispose();
  }

  String getKeyType() {
    return keyType;
  }

  KeyPair getKpair() {
    return kpair;
  }

  String getIdentity() {
    return identity;
  }

  String getComment() {
    return comment;
  }
}
