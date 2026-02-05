package com.jcraft.jsch;

import java.util.Collection;
import java.util.Locale;

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

    String host = session.host;
    if (host == null) {
      throw new JSchException("Cannot verify host certificate: session host is null");
    }
    HostKeyRepository repository = session.getHostKeyRepository();

    boolean caFound = OpenSshCertificateUtil.isCertificateSignedByTrustedCA(repository, host,
        caPublicKeyByteArray);

    if (!caFound) {
      throw new JSchUnknownCAKeyException("Rejected certificate '" + certificate.getId() + "': "
          + "Certification Authority not in the known hosts or revoked for " + host);
    }

    Buffer caPublicKeyBuffer = new Buffer(caPublicKeyByteArray);
    String caPublicKeyAlgorithm = Util.byte2str(caPublicKeyBuffer.getString());
    String certificateId = certificate.getId();

    // check if this is a Host certificate
    if (!certificate.isHostCertificate()) {
      throw new JSchInvalidHostCertificateException("rejected HostKey: certificate id='"
          + certificateId + "' is not a host certificate. Host:" + host);
    }

    if (!certificate.isValidNow()) {
      throw new JSchInvalidHostCertificateException(
          "rejected HostKey: certificate not valid (expired or not yet valid) for id:"
              + certificateId);
    }

    checkSignature(certificate, caPublicKeyAlgorithm, session);

    Collection<String> principals = certificate.getPrincipals();
    if (principals == null || principals.isEmpty()) {
      throw new JSchException("rejected HostKey: invalid principal '" + host
          + "', allowed principals list is null or empty.");
    }

    // Convert host to lowercase for principal matching (same as OpenSSH ssh_login())
    String principalHost = host.toLowerCase(Locale.ROOT);

    if (!principals.contains(principalHost)) {
      throw new JSchException("rejected HostKey: invalid principal '" + principalHost
          + "', allowed principals: " + principals);
    }

    if (!OpenSshCertificateUtil.isEmpty(certificate.getCriticalOptions())) {
      // no critical option defined for host keys yet
      throw new JSchInvalidHostCertificateException(
          "rejected HostKey: unrecognized critical options " + certificate.getCriticalOptions());
    }
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
    byte[][] publicKey =
        OpenSshCertificateUtil.parsePublicKeyComponents(certificate.getSignatureKey());
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
   * matches the algorithm of the signing CA's key. It also validates that the signature algorithm
   * is allowed and available according to the {@code ca_signature_algorithms} configuration.
   * </p>
   *
   * @param certificate the OpenSSH certificate.
   * @param caPublicKeyAlgorithm the expected public key algorithm of the CA.
   * @param session the current session.
   * @return a configured {@link SignatureWrapper} instance.
   * @throws JSchException if the signature algorithm does not match the CA's key algorithm, is not
   *         in the allowed CA signature algorithms list, is not available at runtime, or if the
   *         wrapper cannot be instantiated.
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

    // Validate that the CA signature algorithm is allowed and available at runtime
    session.checkCASignatureAlgorithm(signatureAlgorithm);

    return new SignatureWrapper(signatureAlgorithm, session);
  }

}
