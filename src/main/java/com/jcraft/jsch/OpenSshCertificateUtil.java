package com.jcraft.jsch;

import java.time.Instant;
import java.util.Date;

import static java.nio.charset.StandardCharsets.UTF_8;

class OpenSshCertificateUtil {


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
    String str = new String(s, UTF_8);
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
   * Checks if a CharSequence is empty or null.
   *
   * @param cs the CharSequence to check, may be null
   * @return true if the CharSequence is null or has a length of 0 or less, false otherwise
   */
  static boolean isEmpty(CharSequence cs) {
    return cs == null || cs.length() == 0;
  }

  /**
   * Extracts the key type from a certificate file content string. This method assumes the key type
   * is the first field (index 0) in the space-delimited string.
   *
   * @param certificateFileContent The content of the certificate file as a single string.
   * @return The key type string, or {@code null} if the content is invalid or the field does not
   *         exist.
   * @throws IllegalArgumentException if the certificate content is null or empty after trimming.
   */
  public static String extractKeyType(String certificateFileContent)
      throws IllegalArgumentException {
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
  public static String extractComment(String certificateFileContent)
      throws IllegalArgumentException {
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
  public static String extractKeyData(String certificateFileContent)
      throws IllegalArgumentException {
    return extractSpaceDelimitedString(certificateFileContent, 1);
  }

  /**
   * A private utility method to safely extract a space-delimited string from a certificate content
   * string at a given index. This method is null-safe and handles out-of-bounds indices gracefully
   * by returning {@code null}.
   *
   * @param certificate The string to be parsed, typically representing certificate content.
   * @param index The zero-based index of the field to extract.
   * @return The string field at the specified index, or {@code null} if the input is invalid or the
   *         index is out of bounds.
   */
  public static String extractSpaceDelimitedString(String certificate, int index) {
    if (certificate == null || certificate.trim().isEmpty()) {
      return null;
    }
    String[] fields = certificate.split("\\s+");

    if (index >= 0 && index < fields.length) {
      return fields[index];
    } else {
      return null;
    }
  }


  /**
   * Extracts the key type from encoded key data provided as a byte array. Converts the byte array
   * to a UTF-8 string and delegates to the string version of this method.
   *
   * @param s the encoded key data as a byte array, may be null
   * @return the key type as a string, or an empty string if the input is null/empty
   * @throws IllegalArgumentException if the data format is invalid (no space delimiter found)
   * @see #extractKeyType(String)
   */
  public static String extractKeyType(byte[] s) throws IllegalArgumentException {
    String str = tabToSpaceAndTrim(s);
    return extractKeyType(str);
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
   *
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
   *
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

}
