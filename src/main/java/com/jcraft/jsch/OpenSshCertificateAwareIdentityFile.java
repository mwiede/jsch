package com.jcraft.jsch;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import static com.jcraft.jsch.OpenSshCertificateUtil.extractComment;
import static com.jcraft.jsch.OpenSshCertificateUtil.extractKeyData;
import static com.jcraft.jsch.OpenSshCertificateUtil.extractKeyType;
import static com.jcraft.jsch.OpenSshCertificateUtil.getRawKeyType;
import static com.jcraft.jsch.OpenSshCertificateUtil.trimToEmptyIfNull;
import static java.nio.charset.StandardCharsets.UTF_8;

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
public class OpenSshCertificateAwareIdentityFile implements Identity {

  public static final String SSH_RSA_CERT_V01_AT_OPENSSH_DOT_COM = "ssh-rsa-cert-v01@openssh.com";
  public static final String SSH_DSS_CERT_V01_AT_OPENSSH_DOT_COM = "ssh-dss-cert-v01@openssh.com";
  public static final String ECDSA_SHA2_NISTP256_CERT_V01_AT_OPENSSH_DOT_COM =
      "ecdsa-sha2-nistp256-cert-v01@openssh.com";
  public static final String ECDSA_SHA2_NISTP384_CERT_V01_AT_OPENSSH_DOT_COM =
      "ecdsa-sha2-nistp384-cert-v01@openssh.com";
  public static final String ECDSA_SHA2_NISTP521_CERT_V01_AT_OPENSSH_DOT_COM =
      "ecdsa-sha2-nistp521-cert-v01@openssh.com";
  public static final String SSH_ED25519_CERT_V01_AT_OPENSSH_DOT_COM =
      "ssh-ed25519-cert-v01@openssh.com";
  public static final String RSA_SHA2_256_CERT_V01_AT_OPENSSH_DOT_COM =
      "rsa-sha2-256-cert-v01@openssh.com";
  public static final String RSA_SHA2_512_CERT_V01_AT_OPENSSH_DOT_COM =
      "rsa-sha2-512-cert-v01@openssh.com";


  /**
   * Determines if the given certificate file content as String, represents an OpenSSH certificate.
   *
   * @param certificateFileContent the certificate string to check
   * @return {@code true} if the file content is a supported OpenSSH certificate type, {@code false}
   *         otherwise
   */
  public static boolean isOpenSshCertificate(String certificateFileContent) {
    String certificateKeyType = extractKeyType(trimToEmptyIfNull(certificateFileContent));
    return isOpenSshCertificateKeyType(certificateKeyType);
  }


  /**
   * Determines if the given public key type represents an OpenSSH certificate.
   *
   * @param publicKeyType the public key type string to check
   * @return {@code true} if the type is a supported OpenSSH certificate type, {@code false}
   *         otherwise
   */
  public static boolean isOpenSshCertificateKeyType(String publicKeyType) {
    switch (publicKeyType) {
      case SSH_RSA_CERT_V01_AT_OPENSSH_DOT_COM:
      case SSH_DSS_CERT_V01_AT_OPENSSH_DOT_COM:
      case ECDSA_SHA2_NISTP256_CERT_V01_AT_OPENSSH_DOT_COM:
      case ECDSA_SHA2_NISTP384_CERT_V01_AT_OPENSSH_DOT_COM:
      case ECDSA_SHA2_NISTP521_CERT_V01_AT_OPENSSH_DOT_COM:
      case SSH_ED25519_CERT_V01_AT_OPENSSH_DOT_COM:
      case RSA_SHA2_256_CERT_V01_AT_OPENSSH_DOT_COM:
      case RSA_SHA2_512_CERT_V01_AT_OPENSSH_DOT_COM:
        return true;
      default:
        return false;
    }
  }

  /** parsed certificate. **/
  private final OpenSshCertificate certificate;

  /** the key type declared in the first part of the file **/
  private final String keyType;

  /** The entire certificate as raw bytes */
  private final byte[] publicKeyBlob;

  /** The key pair containing the private key */
  private final KeyPair kpair;

  /** The identity name/path */
  private final String identity;

  /** Optional comment associated with the identity */
  private final String comment;


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
    byte[] pubkey;

    try {
      prvkey = Util.fromFile(prvfile);
      pubkey = Util.fromFile(pubfile);
    } catch (IOException e) {
      throw new JSchException(e.toString(), e);
    }
    return newInstance(prvfile, prvkey, pubkey, instLogger);
  }

  /**
   * Creates a new certificate-aware identity from byte arrays.
   *
   * @param name the identity name
   * @param prvkey the private key bytes
   * @param pubkey the certificate bytes
   * @param instLogger logger instance for debugging
   * @return a new Identity instance
   * @throws JSchException if the certificate cannot be parsed
   */
  static Identity newInstance(String name, byte[] prvkey, byte[] pubkey,
      JSch.InstanceLogger instLogger) throws JSchException {
    String certString = new String(pubkey, UTF_8);
    OpenSshCertificate cert;
    byte[] certPublicKey;
    KeyPair kpair;
    String keyType;
    String comment;
    String base64KeyData;

    try {
      cert = new OpensshCertificateParser(instLogger, certString).parse();
      certPublicKey = cert.getCertificatePublicKey();
      kpair = KeyPair.load(instLogger, prvkey, certPublicKey);
      keyType = extractKeyType(certString);
      base64KeyData = extractKeyData(certString);
      comment = extractComment(certString);


    } catch (IOException | NoSuchAlgorithmException e) {
      throw new JSchException(e.toString(), e);
    }
    return new OpenSshCertificateAwareIdentityFile(name, keyType, base64KeyData, cert, kpair,
        comment);
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
  private OpenSshCertificateAwareIdentityFile(String name, String keyType, String base64KeyData,
      OpenSshCertificate certificate, KeyPair kpair, String comment) {
    this.identity = name;
    this.certificate = certificate;
    this.kpair = kpair;
    this.comment = comment;
    this.keyType = keyType;
    this.publicKeyBlob = Base64.getDecoder().decode(base64KeyData);
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
    String rawKeyType = getRawKeyType(keyType);
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

  public String getKeyType() {
    return keyType;
  }

  public KeyPair getKpair() {
    return kpair;
  }


  public String getIdentity() {
    return identity;
  }

  public String getComment() {
    return comment;
  }
}
