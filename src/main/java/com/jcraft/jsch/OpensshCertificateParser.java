package com.jcraft.jsch;

import com.jcraft.jsch.JSch.InstanceLogger;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;

import static com.jcraft.jsch.OpenSshCertificateAwareIdentityFile.ECDSA_SHA2_NISTP256_CERT_V01_AT_OPENSSH_DOT_COM;
import static com.jcraft.jsch.OpenSshCertificateAwareIdentityFile.ECDSA_SHA2_NISTP384_CERT_V01_AT_OPENSSH_DOT_COM;
import static com.jcraft.jsch.OpenSshCertificateAwareIdentityFile.ECDSA_SHA2_NISTP521_CERT_V01_AT_OPENSSH_DOT_COM;
import static com.jcraft.jsch.OpenSshCertificateAwareIdentityFile.RSA_SHA2_256_CERT_V01_AT_OPENSSH_DOT_COM;
import static com.jcraft.jsch.OpenSshCertificateAwareIdentityFile.RSA_SHA2_512_CERT_V01_AT_OPENSSH_DOT_COM;
import static com.jcraft.jsch.OpenSshCertificateAwareIdentityFile.SSH_DSS_CERT_V01_AT_OPENSSH_DOT_COM;
import static com.jcraft.jsch.OpenSshCertificateAwareIdentityFile.SSH_ED25519_CERT_V01_AT_OPENSSH_DOT_COM;
import static com.jcraft.jsch.OpenSshCertificateAwareIdentityFile.SSH_RSA_CERT_V01_AT_OPENSSH_DOT_COM;
import static com.jcraft.jsch.OpenSshCertificateUtil.extractKeyData;
import static com.jcraft.jsch.OpenSshCertificateUtil.extractKeyType;
import static com.jcraft.jsch.OpenSshCertificateUtil.toDateString;
import static com.jcraft.jsch.OpenSshCertificateUtil.trimToEmptyIfNull;
import static com.jcraft.jsch.Util.fromBase64;
import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Parser for OpenSSH certificate format.
 *
 * <p>
 * This class is responsible for parsing OpenSSH certificates from their string representation
 * (typically found in .pub files) into structured {@link OpenSshCertificate} objects. It handles
 * the base64 decoding and binary parsing of all certificate fields according to the OpenSSH
 * certificate specification.
 * </p>
 *
 * <p>
 * The parser supports all standard OpenSSH certificate types including RSA, DSA, ECDSA, and Ed25519
 * certificates.
 * </p>
 *
 * @see OpenSshCertificate
 * @see <a href="https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys">OpenSSH Certificate
 *      Protocol</a>
 */
public class OpensshCertificateParser {

  private final String keyType;

  private final OpenSshCertificateBuffer buffer;

  private final InstanceLogger instLogger;

  public OpensshCertificateParser(InstanceLogger instLogger, String certificate)
      throws JSchException {
    this.instLogger = instLogger;

    this.keyType = extractKeyType(certificate);

    // Decode
    String base64 = extractKeyData(certificate);


    byte[] keyData = fromBase64(base64.getBytes(UTF_8), 0, base64.getBytes(UTF_8).length);

    buffer = new OpenSshCertificateBuffer(keyData);
  }

  /**
   * Parses the certificate data and returns a complete {@link OpenSshCertificate} object.
   *
   * <p>
   * This method reads all fields from the certificate in the order specified by the OpenSSH
   * certificate format:
   * </p>
   * <ol>
   * <li>Key type</li>
   * <li>Nonce</li>
   * <li>Certificate public key</li>
   * <li>Serial number</li>
   * <li>Certificate type</li>
   * <li>Key ID</li>
   * <li>Valid principals</li>
   * <li>Valid after timestamp</li>
   * <li>Valid before timestamp</li>
   * <li>Critical options</li>
   * <li>Extensions</li>
   * <li>Reserved field</li>
   * <li>Signature key</li>
   * <li>Signature</li>
   * </ol>
   *
   * @return the parsed certificate object
   * @throws IOException if an I/O error occurs during parsing
   * @throws JSchException if the certificate format is invalid or unsupported
   * @throws NoSuchAlgorithmException if a required cryptographic algorithm is not available
   */
  public OpenSshCertificate parse() throws IOException, JSchException, NoSuchAlgorithmException {

    OpenSshCertificate.Builder openSshCertificateBuilder = new OpenSshCertificate.Builder();

    // keyType
    String kTypeFromData = trimToEmptyIfNull(buffer.getString(UTF_8));
    if (kTypeFromData.isEmpty() || !keyType.equals(kTypeFromData)) {
      instLogger.getLogger().log(Logger.WARN,
          "Key type declared does not correspond to the encoded key type: " + keyType + " - "
              + kTypeFromData);
    }

    openSshCertificateBuilder.keyType(kTypeFromData).nonce(buffer.getString());

    // KeyPair.parsePubkeyBlob expect keytype in public key blob
    KeyPair publicKey = parsePublicKey(keyType, buffer);
    openSshCertificateBuilder.certificatePublicKey(publicKey.getPublicKeyBlob())
        .serial(buffer.getLong()).type(buffer.getInt()).id(buffer.getString(UTF_8));

    // Principals
    byte[] principalsBlob = buffer.getBytes();
    OpenSshCertificateBuffer principalsBuffer = new OpenSshCertificateBuffer(principalsBlob);
    Collection<String> principals = principalsBuffer.getStrings();
    openSshCertificateBuilder.principals(principals).validAfter(buffer.getLong())
        .validBefore(buffer.getLong()).criticalOptions(buffer.getCriticalOptions())
        .extensions(buffer.getExtensions()).reserved(buffer.getString(UTF_8))
        .signatureKey(buffer.getString()).signature(buffer.getString());


    OpenSshCertificate certificate = openSshCertificateBuilder.build();

    if (buffer.getReadPosition() != buffer.getWritePosition()) {
      throw new JSchException("Cannot read OpenSSH certificate, got more data than expected: "
          + buffer.getReadPosition() + ", actual: " + buffer.getWritePosition()
          + ". ID of the ca certificate: " + certificate.getId());
    }

    if (!certificate.isValidNow()) {
      instLogger.getLogger().log(Logger.WARN,
          "certificate is not valid. Valid after: " + toDateString(certificate.getValidAfter())
              + " - Valid before: " + toDateString(certificate.getValidBefore()));
    }


    return certificate;
  }


  private KeyPair parsePublicKey(String keyType, Buffer buffer) throws JSchException {
    switch (keyType) {

      case SSH_RSA_CERT_V01_AT_OPENSSH_DOT_COM:
      case RSA_SHA2_256_CERT_V01_AT_OPENSSH_DOT_COM:
      case RSA_SHA2_512_CERT_V01_AT_OPENSSH_DOT_COM:
        byte[] pub_array = buffer.getMPInt(); // e
        byte[] n_array = buffer.getMPInt(); // n
        return new KeyPairRSA(instLogger, n_array, pub_array, null);

      case SSH_DSS_CERT_V01_AT_OPENSSH_DOT_COM:
        byte[] p_array = buffer.getMPInt();
        byte[] q_array = buffer.getMPInt();
        byte[] g_array = buffer.getMPInt();
        byte[] y_array = buffer.getMPInt();
        return new KeyPairDSA(instLogger, p_array, q_array, g_array, y_array, null);

      case ECDSA_SHA2_NISTP256_CERT_V01_AT_OPENSSH_DOT_COM:
      case ECDSA_SHA2_NISTP384_CERT_V01_AT_OPENSSH_DOT_COM:
      case ECDSA_SHA2_NISTP521_CERT_V01_AT_OPENSSH_DOT_COM:
        byte[] name = buffer.getString();
        int len = buffer.getInt();
        int x04 = buffer.getByte();
        byte[] r_array = new byte[(len - 1) / 2];
        byte[] s_array = new byte[(len - 1) / 2];
        buffer.getByte(r_array);
        buffer.getByte(s_array);
        return new KeyPairECDSA(instLogger, name, r_array, s_array, null);

      case SSH_ED25519_CERT_V01_AT_OPENSSH_DOT_COM:
        byte[] ed25519_pub_array = new byte[buffer.getInt()];
        buffer.getByte(ed25519_pub_array);
        return new KeyPairEd25519(instLogger, ed25519_pub_array, null);

      default:
        throw new JSchException("Unsupported Algorithm for Certificate public key: " + keyType);
    }
  }
}
