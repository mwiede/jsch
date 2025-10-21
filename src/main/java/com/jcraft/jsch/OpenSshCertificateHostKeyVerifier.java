package com.jcraft.jsch;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * A verifier for OpenSSH host certificates.
 * <p>
 * This class provides the logic to authenticate a remote host based on an OpenSSH certificate
 * presented during the key exchange process. The verification ensures that the host certificate was
 * signed by a trusted Certificate Authority (CA) listed in the user's {@code known_hosts} file.
 * </p>
 * The verification process includes:
 * <ul>
 * <li>Checking that the signing CA is trusted for the given host.</li>
 * <li>Validating the certificate's type, validity period, and principals (hostnames).</li>
 * <li>Cryptographically verifying the certificate's signature.</li>
 * <li>Ensuring no unrecognized critical options are present.</li>
 * </ul>
 */
class OpenSshCertificateHostKeyVerifier {

  /**
   * Performs a complete verification of a host's OpenSSH certificate.
   * <p>
   * This is the main entry point for host certificate validation. It orchestrates all the necessary
   * checks to ensure the certificate is valid and signed by a trusted Certificate Authority (CA)
   * for the connected host.
   * </p>
   *
   * @param session the current JSch session.
   * @param certificate the certificate to check.
   * @throws JSchException if the certificate is invalid, expired, not signed by a trusted CA, or
   *         fails any other validation check. Throws specific subclasses of {@link JSchException}
   *         for different failure reasons.
   */
  static void checkHostCertificate(Session session, OpenSshCertificate certificate)
      throws JSchException {

    byte[] caPublicKeyByteArray = certificate.getSignatureKey();

    String base64CaPublicKey =
        Util.byte2str(Util.toBase64(caPublicKeyByteArray, 0, caPublicKeyByteArray.length, true));

    String host = session.host;
    HostKeyRepository repository = session.getHostKeyRepository();

    boolean caFound =
        OpenSshCertificateUtil.isCertificateSignedByTrustedCA(repository, host, base64CaPublicKey);

    if (!caFound) {
      throw new JSchUnknownCAKeyException("Rejected certificate '" + certificate.getId() + "': "
          + "Certification Authority not in the known hosts or revoked for " + host);
    }

    Buffer caPublicKeyBuffer = new Buffer(caPublicKeyByteArray);
    String caPublicKeyAlgorithm = Util.byte2str(caPublicKeyBuffer.getString());
    String certificateId = certificate.getId();

    // check if the certificate is a
    if (!certificate.isHostCertificate()) {
      throw new JSchInvalidHostCertificateException("reject HostKey: certificate id='"
          + certificateId + "' is not a host certificate. Host:" + host);
    }

    if (!certificate.isValidNow()) {
      throw new JSchInvalidHostCertificateException(
          "rejected HostKey: signature verification failed, " + "certificate expired for id:"
              + certificateId);
    }

    checkSignature(certificate, caPublicKeyAlgorithm, session);

    // "As a special case, a zero-length "valid principals" field means the certificate is valid for
    // any principal of the specified type."
    // Empty principals in a host certificate mean the certificate is valid for any host.
    Collection<String> principals = certificate.getPrincipals();
    if (principals != null && !principals.isEmpty()) {
      if (!principals.contains(host)) {
        throw new JSchException("rejected HostKey: invalid principal '" + host
            + "', allowed principals: " + principals);
      }
    }

    if (!OpenSshCertificateUtil.isEmpty(certificate.getCriticalOptions())) {
      // no critical option defined for host keys yet
      throw new JSchInvalidHostCertificateException(
          "rejected HostKey: unrecognized critical options " + certificate.getCriticalOptions());
    }
  }

  /**
   * Parses a raw public key byte array into its constituent mathematical components.
   * <p>
   * Different public key algorithms (RSA, DSS, ECDSA, etc.) have different structures. This method
   * decodes the algorithm-specific format and returns the components needed for cryptographic
   * operations.
   * </p>
   *
   * @param certificatePublicKey the raw byte array of the public key blob.
   * @return A 2D byte array where each inner array is a component of the public key (e.g., for RSA,
   *         it returns {exponent, modulus}).
   * @throws JSchException if the public key algorithm is unknown or the key format is corrupt.
   */
  static byte[][] parsePublicKey(byte[] certificatePublicKey) throws JSchException {
    Buffer buffer = new Buffer(certificatePublicKey);
    String algorithm = Util.byte2str(buffer.getString());

    if (algorithm.startsWith("ssh-rsa") || algorithm.startsWith("rsa-")) {
      byte[] ee = buffer.getMPInt();
      byte[] n = buffer.getMPInt();
      return new byte[][] {ee, n};
    }

    if (algorithm.startsWith("ssh-dss")) {
      byte[] p = buffer.getMPInt();
      byte[] q = buffer.getMPInt();
      byte[] g = buffer.getMPInt();
      byte[] y = buffer.getMPInt();
      return new byte[][] {y, p, q, g};
    }

    if (algorithm.startsWith("ecdsa-sha2-")) {
      // https://www.rfc-editor.org/rfc/rfc5656#section-3.1
      // The string [identifier] is the identifier of the elliptic curve domain parameters.
      String identifier = Util.byte2str(buffer.getString());
      int len = buffer.getInt();
      int x04 = buffer.getByte();
      byte[] r = new byte[(len - 1) / 2];
      byte[] s = new byte[(len - 1) / 2];
      buffer.getByte(r);
      buffer.getByte(s);
      return new byte[][] {r, s};
    }

    if (algorithm.startsWith("ssh-ed25519") || algorithm.startsWith("ssh-ed448")) {
      int keyLength = buffer.getInt();
      byte[] edXXX_pub_array = new byte[keyLength];
      buffer.getByte(edXXX_pub_array);
      return new byte[][] {edXXX_pub_array};
    }
    throw new JSchUnknownPublicKeyAlgorithmException(
        "Unknown algorithm '" + algorithm.trim() + "'");
  }

  /**
   * Verifies the cryptographic signature of the certificate.
   * <p>
   * This method ensures that the certificate was actually signed by the private key corresponding
   * to the public key of the Certificate Authority.
   * </p>
   *
   * @param certificate the certificate to verify.
   * @param caPublicKeyAlgorithm the algorithm of the CA's public key.
   * @throws JSchException if the signature algorithm does not match the CA key algorithm or if the
   *         signature is cryptographically invalid.
   */
  static void checkSignature(OpenSshCertificate certificate, String caPublicKeyAlgorithm,
      Session session) throws JSchException {
    // Check signature
    SignatureWrapper signature = getSignatureWrapper(certificate, caPublicKeyAlgorithm, session);
    byte[][] publicKey = parsePublicKey(certificate.getSignatureKey());
    boolean verified;
    try {
      signature.init();
      signature.setPubKey(publicKey);
      signature.update(certificate.getMessage());
      verified = signature.verify(certificate.getSignature());
    } catch (Exception e) {
      throw new JSchException("invalid signature key", e);
    }

    if (!verified) {
      throw new JSchInvalidHostCertificateException(
          "rejected HostKey: signature verification failed");
    }
  }

  /**
   * Creates and validates a {@link SignatureWrapper} for the certificate.
   * <p>
   * This helper method extracts the signature algorithm from the certificate and verifies that it
   * matches the algorithm of the signing CA's key.
   * </p>
   *
   * @param certificate the OpenSSH certificate.
   * @param caPublicKeyAlgorithm the expected public key algorithm of the CA.
   * @return a configured {@link SignatureWrapper} instance.
   * @throws JSchException if the signature algorithm does not match the CA's key algorithm, or if
   *         the wrapper cannot be instantiated.
   */
  static SignatureWrapper getSignatureWrapper(OpenSshCertificate certificate,
      String caPublicKeyAlgorithm, Session session) throws JSchException {
    byte[] certificateSignature = certificate.getSignature();
    Buffer signatureBuffer = new Buffer(certificateSignature);
    String signatureAlgorithm = Util.byte2str(signatureBuffer.getString());

    if (!caPublicKeyAlgorithm.equals(signatureAlgorithm)) {
      throw new JSchInvalidHostCertificateException(
          "rejected HostKey: signature verification failed, " + "signature algorithm: '"
              + signatureAlgorithm + "' - CA public Key algorithm: '" + caPublicKeyAlgorithm + "'");
    }

    return new SignatureWrapper(signatureAlgorithm, session);
  }

}
