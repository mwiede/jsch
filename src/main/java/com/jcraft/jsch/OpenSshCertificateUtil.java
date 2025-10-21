package com.jcraft.jsch;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;

class OpenSshCertificateUtil {

  /**
   * Predicate that identifies Certificate Authority (CA) public key entries in a known_hosts file.
   * <p>
   * This predicate tests whether a {@link HostKey} represents a trusted CA entry, identified by the
   * {@code @cert-authority} marker in the known_hosts file. CA entries are used to validate OpenSSH
   * certificates presented by hosts during authentication.
   * </p>
   */
  static Predicate<HostKey> isKnownHostCaPublicKeyEntry =
      hostKey -> Objects.nonNull(hostKey) && "@cert-authority".equals(hostKey.getMarker());

  /**
   * Predicate that identifies revoked key entries in a known_hosts file.
   * <p>
   * This predicate tests whether a {@link HostKey} is marked as revoked (using the {@code @revoked}
   * marker) or is {@code null}. It implements fail-closed security semantics by treating
   * {@code null} entries as revoked.
   * </p>
   */
  static Predicate<HostKey> isMarkedRevoked =
      hostKey -> hostKey == null || "@revoked".equals(hostKey.getMarker());

  /**
   * Converts a byte array to a UTF-8 string, replaces tab characters with spaces, and trims
   * whitespace.
   *
   * @param s the byte array to convert and process, may be null
   * @return the processed string with tabs converted to spaces and whitespace trimmed, or an empty
   *         string if the input is null
   * @see #tabToSpaceAndTrim(String)
   */
  static String tabToSpaceAndTrim(byte[] s) {
    String str = new String(s, StandardCharsets.UTF_8);
    return tabToSpaceAndTrim(str);
  }

  /**
   * Replaces all tab characters in the input string with space characters and trims leading and
   * trailing whitespace.
   *
   * @param s the string to process, may be null
   * @return the processed string with tabs converted to spaces and whitespace trimmed, or an empty
   *         string if the input is null
   * @see #trimToEmptyIfNull(String)
   */
  static String tabToSpaceAndTrim(String s) {
    if (s != null) {
      s = s.replace('\t', ' ');
    }
    return trimToEmptyIfNull(s);
  }

  /**
   * Trims leading and trailing whitespace from the input string. Returns an empty string if the
   * input is null.
   *
   * @param s the string to trim, may be null
   * @return the trimmed string, or an empty string if the input is null
   */
  static String trimToEmptyIfNull(String s) {
    if (s == null) {
      return "";
    } else {
      return s.trim();
    }
  }

  /**
   * Checks if a String is empty or null.
   *
   * @param string the String to check, may be null
   * @return true if the CharSequence is null or has a length of 0, false otherwise
   */
  static boolean isEmpty(String string) {
    return string == null || string.isEmpty();
  }

  /**
   * Checks if a Collection is empty or null.
   *
   * @param c the Collection to check, may be null
   * @return true if the Collection is null or has 0 elements, false otherwise
   */
  static boolean isEmpty(Collection<?> c) {
    return c == null || c.isEmpty();
  }

  /**
   * Checks if a Map is empty or null.
   *
   * @param c the Map to check, may be null
   * @return true if the Map is null or has 0 elements, false otherwise
   */
  static boolean isEmpty(Map<?, ?> c) {
    return c == null || c.isEmpty();
  }

  /**
   * Extracts the key type from a certificate file content byte array. This method assumes the key
   * type is the first field (index 0) in the space-delimited string.
   *
   * @param certificateFileContent The content of the certificate file as a byte array.
   * @return The key type string, or {@code null} if the content is invalid or the field does not
   *         exist.
   * @throws IllegalArgumentException if the certificate content is null or empty after trimming.
   */
  static byte[] extractKeyType(byte[] certificateFileContent) throws IllegalArgumentException {
    return extractSpaceDelimitedString(certificateFileContent, 0);
  }

  /**
   * Extracts the comment from a certificate file content string. This method assumes the comment is
   * the third field (index 2) in the space-delimited string.
   *
   * @param certificateFileContent The content of the certificate file as a single string.
   * @return The comment string, or {@code null} if the content is invalid or the field does not
   *         exist.
   * @throws IllegalArgumentException if the certificate content is null or empty after trimming.
   */
  static byte[] extractComment(byte[] certificateFileContent) throws IllegalArgumentException {
    return extractSpaceDelimitedString(certificateFileContent, 2);
  }

  /**
   * Extracts the key data from a certificate file content string. This method assumes the key data
   * is the second field (index 1) in the space-delimited string.
   *
   * @param certificateFileContent The content of the certificate file as a single string.
   * @return The key data string, or {@code null} if the content is invalid or the field does not
   *         exist.
   */
  static byte[] extractKeyData(byte[] certificateFileContent) throws IllegalArgumentException {
    return extractSpaceDelimitedString(certificateFileContent, 1);
  }

  /**
   * Checks if a byte represents a whitespace character (space, tab, newline, or carriage return).
   *
   * @param b the byte to check
   * @return true if the byte is a whitespace character, false otherwise
   */
  private static boolean isWhitespace(byte b) {
    return b == ' ' || b == '\t' || b == '\n' || b == '\r';
  }

  /**
   * A utility method to safely extract a space-delimited field from a certificate content byte
   * array at a given index. This method avoids String allocation by working directly with bytes and
   * returning a byte array. It handles whitespace (space, tab, newline, carriage return) as
   * delimiters.
   *
   * @param certificate The byte array to be parsed, typically representing certificate content.
   * @param index The zero-based index of the field to extract.
   * @return The byte array field at the specified index, or {@code null} if the input is invalid or
   *         the index is out of bounds.
   */
  static byte[] extractSpaceDelimitedString(byte[] certificate, int index) {
    if (certificate == null || certificate.length == 0) {
      return null;
    }

    int fieldCount = 0;
    int fieldStart = -1;
    int i = 0;

    // Skip leading whitespace
    while (i < certificate.length && isWhitespace(certificate[i])) {
      i++;
    }

    while (i < certificate.length) {
      // Found start of a field
      if (!isWhitespace(certificate[i])) {
        if (fieldStart == -1) {
          fieldStart = i;
        }
        i++;
      } else {
        // Found end of a field
        if (fieldStart != -1) {
          if (fieldCount == index) {
            // This is the field we want - copy and return it
            int length = i - fieldStart;
            byte[] result = new byte[length];
            System.arraycopy(certificate, fieldStart, result, 0, length);
            return result;
          }
          fieldCount++;
          fieldStart = -1;
        }

        // Skip whitespace
        while (i < certificate.length && isWhitespace(certificate[i])) {
          i++;
        }
      }
    }
    // Handle last field (no trailing whitespace)
    if (fieldStart != -1 && fieldCount == index) {
      int length = i - fieldStart;
      byte[] result = new byte[length];
      System.arraycopy(certificate, fieldStart, result, 0, length);
      return result;
    }

    return null;
  }

  /**
   * Determines whether the given {@link OpenSshCertificate} is valid at the current local system
   * time.
   *
   * @param cert to check
   * @return {@code true} if the certificate is valid according to its timestamps, {@code false}
   *         otherwise
   */
  static boolean isValidNow(OpenSshCertificate cert) {

    long now = Instant.now().getEpochSecond();

    return Long.compareUnsigned(cert.getValidAfter(), now) <= 0
        && Long.compareUnsigned(now, cert.getValidBefore()) < 0;
  }

  /**
   * Converts a Unix timestamp to a {@link Date} string representation.
   * <p>
   * If the timestamp is negative, it indicates an infinite expiration time, and the method returns
   * the string "infinity". Otherwise, it converts the timestamp from seconds to milliseconds and
   * returns the default string representation of the resulting {@link Date} object.
   *
   * @param timestamp The Unix timestamp in seconds.
   * @return A string representing the date, or "infinity" if the timestamp is negative.
   */
  static String toDateString(long timestamp) {
    if (timestamp < 0) {
      return "infinity";
    }
    return SftpATTRS.toDateString(timestamp);
  }

  /**
   * Extracts the raw key type from a given key type string.
   * <p>
   * This method searches for the first occurrence of the substring "-cert" and returns all
   * characters that appear before it. If the substring is not found, the original string is
   * returned unchanged.
   *
   * @param keyType The full key type string, may be null.
   * @return The raw key type (e.g., "ssh-rsa"), more in general the substring before the first
   *         occurrence of "-cert", or the original string if "-cert" is not found, or null if the
   *         input is null.
   */
  static String getRawKeyType(String keyType) {
    if (isEmpty(keyType)) {
      return null;
    }
    int index = keyType.indexOf("-cert");
    if (index == -1) {
      return keyType; // "-cert" not found, return original string
    }

    return keyType.substring(0, index);
  }

  /**
   * Checks if a given byte array represents an OpenSSH host certificate.
   * <p>
   * This method parses the provided byte array to determine if it conforms to the structure of an
   * OpenSSH certificate and, if so, verifies that its type is a host certificate. It performs
   * checks for null or empty input, validates the key type, and then extracts the certificate type
   * from the buffer.
   *
   * @param instLogger An instance of {@link JSch.InstanceLogger} for logging purposes.
   * @param bytes The byte array containing the certificate data to be checked.
   * @return {@code true} if the byte array represents a valid OpenSSH host certificate;
   *         {@code false} otherwise.
   * @throws JSchException if there is an issue parsing the certificate data, such as malformed
   *         data.
   */
  static boolean isOpenSshHostCertificate(JSch.InstanceLogger instLogger, byte[] bytes)
      throws JSchException {
    if (bytes == null || bytes.length == 0) {
      return false;
    }

    OpenSshCertificateBuffer buffer = new OpenSshCertificateBuffer(bytes);

    String keyType = Util.byte2str(buffer.getString(), StandardCharsets.UTF_8);
    if (isEmpty(keyType)
        || !OpenSshCertificateAwareIdentityFile.isOpenSshCertificateKeyType(keyType)) {
      return false;
    }

    // discard nonce
    buffer.getString();
    // public key
    OpenSshCertificateParser.parsePublicKey(instLogger, keyType, buffer);
    // serial
    buffer.getLong();
    // type
    int certificateType = buffer.getInt();

    return certificateType == OpenSshCertificate.SSH2_CERT_TYPE_HOST;
  }

  /**
   * Filters out OpenSSH certificate types whose underlying signature algorithms are unavailable.
   * <p>
   * This method ensures that JSch does not attempt to negotiate certificate-based host key
   * algorithms when the corresponding signature implementation is unavailable on the system. This
   * prevents connection failures that would occur if JSch negotiated a certificate type (e.g.,
   * {@code ssh-ed25519-cert-v01@openssh.com}) but could not verify it because the base signature
   * algorithm (e.g., {@code ssh-ed25519}) requires Java 15+ or Bouncy Castle.
   * </p>
   *
   * <h3>Algorithm Mapping</h3>
   * <p>
   * The method maintains an internal mapping between base signature algorithms and their
   * certificate counterparts:
   * </p>
   * <ul>
   * <li>{@code ssh-ed25519} → {@code ssh-ed25519-cert-v01@openssh.com}</li>
   * <li>{@code ssh-ed448} → {@code ssh-ed448-cert-v01@openssh.com}</li>
   * <li>{@code ssh-rsa} → {@code ssh-rsa-cert-v01@openssh.com},
   * {@code rsa-sha2-256-cert-v01@openssh.com}, {@code rsa-sha2-512-cert-v01@openssh.com}</li>
   * <li>{@code rsa-sha2-256} → {@code rsa-sha2-256-cert-v01@openssh.com}</li>
   * <li>{@code rsa-sha2-512} → {@code rsa-sha2-512-cert-v01@openssh.com}</li>
   * <li>{@code ssh-dss} → {@code ssh-dss-cert-v01@openssh.com}</li>
   * <li>{@code ecdsa-sha2-nistp256} → {@code ecdsa-sha2-nistp256-cert-v01@openssh.com}</li>
   * <li>{@code ecdsa-sha2-nistp384} → {@code ecdsa-sha2-nistp384-cert-v01@openssh.com}</li>
   * <li>{@code ecdsa-sha2-nistp521} → {@code ecdsa-sha2-nistp521-cert-v01@openssh.com}</li>
   * </ul>
   * <p>
   * <b>Note:</b> RSA has special handling because {@code ssh-rsa} being unavailable implies that
   * RSA signature verification is completely unavailable, so all RSA-based certificate types are
   * removed.
   * </p>
   *
   * @param serverHostKey comma-separated list of server host key algorithms to filter. This
   *        typically contains a mix of plain key algorithms (e.g., {@code ssh-ed25519}) and
   *        certificate types (e.g., {@code ssh-ed25519-cert-v01@openssh.com}). May be {@code null}.
   * @param unavailableSignatures array of base signature algorithms that are unavailable on this
   *        system, as determined by {@link Session#checkSignatures(String)}. Each entry is a plain
   *        algorithm name like {@code ssh-ed25519} or {@code rsa-sha2-512}. May be {@code null} or
   *        empty if all signature algorithms are available.
   * @return the filtered comma-separated list of server host key algorithms with unavailable
   *         certificate types removed, or {@code null} if all algorithms were filtered out. If
   *         {@code unavailableSignatures} is {@code null} or empty, returns {@code serverHostKey}
   *         unchanged.
   */
  static String filterUnavailableCertTypes(String serverHostKey, String[] unavailableSignatures) {
    if (unavailableSignatures == null || unavailableSignatures.length == 0) {
      return serverHostKey;
    }

    if (JSch.getLogger().isEnabled(Logger.DEBUG)) {
      JSch.getLogger().log(Logger.DEBUG,
          "server_host_key proposal before removing unavailable cert types is: " + serverHostKey);
    }

    // Build list of certificate types to remove based on unavailable base signatures
    List<String> certsToRemove = new ArrayList<String>();

    for (String unavailableSig : unavailableSignatures) {
      // For each unavailable signature, add corresponding certificate types
      if ("ssh-ed25519".equals(unavailableSig)) {
        certsToRemove.add("ssh-ed25519-cert-v01@openssh.com");
      } else if ("ssh-ed448".equals(unavailableSig)) {
        certsToRemove.add("ssh-ed448-cert-v01@openssh.com");
      } else if ("ssh-rsa".equals(unavailableSig)) {
        certsToRemove.add("ssh-rsa-cert-v01@openssh.com");
        certsToRemove.add("rsa-sha2-256-cert-v01@openssh.com");
        certsToRemove.add("rsa-sha2-512-cert-v01@openssh.com");
      } else if ("rsa-sha2-256".equals(unavailableSig)) {
        certsToRemove.add("rsa-sha2-256-cert-v01@openssh.com");
      } else if ("rsa-sha2-512".equals(unavailableSig)) {
        certsToRemove.add("rsa-sha2-512-cert-v01@openssh.com");
      } else if ("ssh-dss".equals(unavailableSig)) {
        certsToRemove.add("ssh-dss-cert-v01@openssh.com");
      } else if ("ecdsa-sha2-nistp256".equals(unavailableSig)) {
        certsToRemove.add("ecdsa-sha2-nistp256-cert-v01@openssh.com");
      } else if ("ecdsa-sha2-nistp384".equals(unavailableSig)) {
        certsToRemove.add("ecdsa-sha2-nistp384-cert-v01@openssh.com");
      } else if ("ecdsa-sha2-nistp521".equals(unavailableSig)) {
        certsToRemove.add("ecdsa-sha2-nistp521-cert-v01@openssh.com");
      }
    }

    if (certsToRemove.size() > 0) {
      String[] certsArray = new String[certsToRemove.size()];
      certsToRemove.toArray(certsArray);
      serverHostKey = Util.diffString(serverHostKey, certsArray);

      if (JSch.getLogger().isEnabled(Logger.DEBUG)) {
        for (String cert : certsArray) {
          JSch.getLogger().log(Logger.DEBUG, "Removing " + cert + " (base algorithm unavailable)");
        }
        JSch.getLogger().log(Logger.DEBUG,
            "server_host_key proposal after removing unavailable cert types is: " + serverHostKey);
      }
    }
    return serverHostKey;
  }

  /**
   * Validates that a certificate is signed by a trusted, non-revoked Certificate Authority.
   * <p>
   * This method performs the critical CA validation step for OpenSSH certificate authentication. It
   * verifies that:
   * </p>
   * <ol>
   * <li>The CA public key exists in the known_hosts file with {@code @cert-authority} marker</li>
   * <li>The CA entry matches the connecting host's pattern</li>
   * <li>The CA key has not been revoked (no {@code @revoked} entry for same key)</li>
   * <li>The certificate was signed by this CA (CA public key matches)</li>
   * </ol>
   *
   * <h3>Validation Flow</h3>
   * <p>
   * The validation follows these steps:
   * </p>
   *
   * <pre>
   * 1. Retrieve all {@code @cert-authority} entries from known_hosts
   * 2. Filter to only non-null entries
   * 3. Check each CA to ensure it hasn't been revoked
   * 4. Test if any remaining CA:
   *    - Matches the host pattern (e.g., *.example.com matches host.example.com)
   *    - Has a public key that equals the certificate's signing CA key
   * </pre>
   *
   * <h3>Revocation Checking</h3>
   * <p>
   * A CA is considered revoked if there exists a {@code @revoked} entry in the known_hosts file
   * with the same public key value. The revocation check uses
   * {@link #hasBeenRevoked(HostKeyRepository, HostKey)} to ensure that compromised CA keys are
   * rejected even if they appear as {@code @cert-authority}.
   * </p>
   *
   *
   * @param repository the {@link HostKeyRepository} containing known_hosts entries, must not be
   *        {@code null}
   * @param host the hostname or host pattern being connected to (e.g., "host.example.com" or
   *        "[host.example.com]:2222"), must not be {@code null}
   * @param base64CaPublicKey the Base64-encoded CA public key from the certificate that needs
   *        validation, must not be {@code null}
   * @return {@code true} if a trusted, non-revoked CA matching the host pattern signed the
   *         certificate; {@code false} if no matching CA exists, all matching CAs are revoked, or
   *         the CA key doesn't match
   */
  static boolean isCertificateSignedByTrustedCA(HostKeyRepository repository, String host,
      String base64CaPublicKey) throws JSchException {
    final Set<HostKey> revokedKeys = getRevokedKeys(repository);
    byte[] publicKeyBytes = Util.fromBase64(base64CaPublicKey.getBytes(StandardCharsets.UTF_8));

    return getTrustedCAs(repository).stream().filter(Objects::nonNull)
        .filter(hostkey -> !hasBeenRevoked(repository, hostkey)).anyMatch(trustedCA -> {
          try {
            byte[] trustedCAKeyBytes =
                Util.fromBase64(trustedCA.getKey().getBytes(StandardCharsets.UTF_8));
            return trustedCA.isWildcardMatched(host) && trustedCA.getKey() != null
                && Arrays.equals(trustedCAKeyBytes, publicKeyBytes);
          } catch (Exception e) {
            return false;
          }
        });
  }

  /**
   * Retrieves all trusted Certificate Authority (CA) host keys from the repository.
   * <p>
   * This method extracts all entries from the known_hosts file that are marked with the
   * {@code @cert-authority} marker, which designates them as trusted CAs for certificate-based host
   * authentication.
   * </p>
   *
   * @param knownHosts the {@link HostKeyRepository} to query (typically populated from a
   *        known_hosts file), may be empty but must not be {@code null}
   * @return a {@link Set} of {@link HostKey} objects representing all CA entries; returns empty set
   *         if repository is empty or contains no CA entries, never returns {@code null}
   */
  static Set<HostKey> getTrustedCAs(HostKeyRepository knownHosts) {
    HostKey[] hostKeys = knownHosts.getHostKey();
    return hostKeys == null ? new HashSet<>()
        : Arrays.stream(hostKeys).filter(isKnownHostCaPublicKeyEntry).collect(Collectors.toSet());
  }

  /**
   * Retrieves all revoked key entries from the repository.
   * <p>
   * This method extracts all entries from the known_hosts file that are marked with the
   * {@code @revoked} marker, indicating keys that have been explicitly blacklisted and must not be
   * trusted for authentication.
   * </p>
   * <p>
   * Revoked entries take precedence over trusted entries. If a key appears in both:
   * </p>
   * <ul>
   * <li>A {@code @cert-authority} or regular trusted entry, AND</li>
   * <li>A {@code @revoked} entry</li>
   * </ul>
   * <p>
   * The key must be rejected. Use {@link #hasBeenRevoked(HostKeyRepository, HostKey)} to check if a
   * specific key has been revoked.
   * </p>
   *
   * @param knownHosts the {@link HostKeyRepository} to query (typically populated from a
   *        known_hosts file), may be empty but must not be {@code null}
   * @return a {@link Set} of {@link HostKey} objects representing all revoked entries (includes
   *         {@code null} entries due to fail-closed security); returns empty set if repository
   *         contains no revoked entries, never returns {@code null}
   */
  static Set<HostKey> getRevokedKeys(HostKeyRepository knownHosts) {
    HostKey[] hostKeys = knownHosts.getHostKey();
    return hostKeys == null ? new HashSet<>()
        : Arrays.stream(hostKeys).filter(isMarkedRevoked).collect(Collectors.toSet());
  }

  /**
   * Checks if a given host key has been revoked.
   * <p>
   * This method determines whether a {@link HostKey} appears in the known_hosts file with the
   * {@code @revoked} marker, indicating it should not be trusted for authentication. It compares
   * the key's public key value against all revoked entries.
   * </p>
   *
   * @param knownHosts the {@link HostKeyRepository} to query for revoked entries, must not be
   *        {@code null}
   * @param key the {@link HostKey} to check for revocation, may be {@code null}
   * @return {@code true} if {@code key} is {@code null} (fail-closed) or if the key's public key
   *         value matches any {@code @revoked} entry in the repository; {@code false} if the key is
   *         valid and not revoked
   */
  static boolean hasBeenRevoked(HostKeyRepository knownHosts, HostKey key) {
    if (key == null) {
      return true;
    }
    return getRevokedKeys(knownHosts).stream().filter(Objects::nonNull)
        .anyMatch(revokedKey -> revokedKey.getKey().equals(key.getKey()));
  }
}
