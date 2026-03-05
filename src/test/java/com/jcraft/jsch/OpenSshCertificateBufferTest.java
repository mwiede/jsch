package com.jcraft.jsch;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link OpenSshCertificateBuffer}.
 *
 * <p>
 * This test class verifies the correct behavior of the {@code OpenSshCertificateBuffer} class,
 * which is responsible for parsing OpenSSH certificate data structures. The tests focus on the
 * {@link OpenSshCertificateBuffer#getBytes()} method, ensuring proper handling of:
 * </p>
 * <ul>
 * <li>Valid length-prefixed byte arrays</li>
 * <li>Empty data arrays</li>
 * <li>Invalid data with negative length prefixes</li>
 * <li>Invalid data where the length prefix exceeds available data</li>
 * <li>Sequential reads from the buffer</li>
 * </ul>
 *
 * @see OpenSshCertificateBuffer
 */
class OpenSshCertificateBufferTest {

  /**
   * Helper method to create a buffer with a length-prefixed byte array.
   *
   * <p>
   * The format follows the SSH wire protocol: 4 bytes (big-endian length) followed by the data
   * bytes.
   * </p>
   *
   * @param data the data bytes to prefix with length
   * @return byte array containing the length prefix followed by the data
   */
  private byte[] createLengthPrefixedData(byte[] data) {
    byte[] result = new byte[4 + data.length];
    int len = data.length;
    result[0] = (byte) ((len >> 24) & 0xff);
    result[1] = (byte) ((len >> 16) & 0xff);
    result[2] = (byte) ((len >> 8) & 0xff);
    result[3] = (byte) (len & 0xff);
    System.arraycopy(data, 0, result, 4, data.length);
    return result;
  }

  /**
   * Helper method to create a buffer with a specific length prefix that may not match the actual
   * data length.
   *
   * <p>
   * This is useful for testing error conditions where the length prefix is intentionally incorrect.
   * </p>
   *
   * @param length the length value to encode in the prefix (may differ from actual data length)
   * @param data the actual data bytes to include after the prefix
   * @return byte array containing the specified length prefix followed by the data
   */
  private byte[] createLengthPrefixedDataWithLength(int length, byte[] data) {
    byte[] result = new byte[4 + data.length];
    result[0] = (byte) ((length >> 24) & 0xff);
    result[1] = (byte) ((length >> 16) & 0xff);
    result[2] = (byte) ((length >> 8) & 0xff);
    result[3] = (byte) (length & 0xff);
    System.arraycopy(data, 0, result, 4, data.length);
    return result;
  }

  /**
   * Tests that {@code getBytes()} correctly reads a valid length-prefixed byte array.
   *
   * <p>
   * Given a buffer containing properly formatted length-prefixed data, the method should return the
   * exact data bytes without the length prefix.
   * </p>
   */
  @Test
  void getBytes_validData_returnsCorrectBytes() {
    byte[] data = {0x01, 0x02, 0x03, 0x04, 0x05};
    byte[] bufferData = createLengthPrefixedData(data);

    OpenSshCertificateBuffer buffer = new OpenSshCertificateBuffer(bufferData);
    byte[] result = buffer.getBytes();

    assertArrayEquals(data, result);
  }

  /**
   * Tests that {@code getBytes()} correctly handles an empty data array.
   *
   * <p>
   * When the length prefix is zero, the method should return an empty byte array without throwing
   * any exceptions.
   * </p>
   */
  @Test
  void getBytes_emptyData_returnsEmptyArray() {
    byte[] data = {};
    byte[] bufferData = createLengthPrefixedData(data);

    OpenSshCertificateBuffer buffer = new OpenSshCertificateBuffer(bufferData);
    byte[] result = buffer.getBytes();

    assertArrayEquals(data, result);
    assertEquals(0, result.length);
  }

  /**
   * Tests that {@code getBytes()} throws an exception when the length prefix is negative.
   *
   * <p>
   * A negative length value (e.g., 0xFFFFFFFF interpreted as -1) indicates malformed certificate
   * data. The method should throw an {@link IllegalArgumentException} with a descriptive message
   * rather than attempting to allocate a negative-sized array.
   * </p>
   */
  @Test
  void getBytes_negativeLength_throwsIllegalArgumentException() {
    // Create buffer with negative length (-1 = 0xFFFFFFFF in unsigned, but interpreted as -1)
    byte[] bufferData = {(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 0x01, 0x02};

    OpenSshCertificateBuffer buffer = new OpenSshCertificateBuffer(bufferData);

    IllegalArgumentException exception =
        assertThrows(IllegalArgumentException.class, buffer::getBytes);
    assertEquals("Invalid length in certificate data: negative length -1", exception.getMessage());
  }

  /**
   * Tests that {@code getBytes()} throws an exception when the length prefix exceeds available
   * data.
   *
   * <p>
   * When the length prefix claims more bytes than are actually available in the buffer, the method
   * should throw an {@link IllegalArgumentException} rather than reading beyond the buffer bounds
   * or returning incomplete data.
   * </p>
   */
  @Test
  void getBytes_lengthExceedsAvailableData_throwsIllegalArgumentException() {
    // Create buffer claiming 100 bytes but only having 5
    byte[] actualData = {0x01, 0x02, 0x03, 0x04, 0x05};
    byte[] bufferData = createLengthPrefixedDataWithLength(100, actualData);

    OpenSshCertificateBuffer buffer = new OpenSshCertificateBuffer(bufferData);

    IllegalArgumentException exception =
        assertThrows(IllegalArgumentException.class, buffer::getBytes);
    assertEquals("Invalid length in certificate data: requested 100 bytes but only 5 available",
        exception.getMessage());
  }

  /**
   * Tests that {@code getBytes()} succeeds when the length prefix exactly matches available data.
   *
   * <p>
   * This is a boundary condition test to ensure that the method correctly handles the case where
   * all remaining buffer data is consumed by a single read operation.
   * </p>
   */
  @Test
  void getBytes_lengthExactlyMatchesAvailableData_succeeds() {
    byte[] data = {0x0A, 0x0B, 0x0C};
    byte[] bufferData = createLengthPrefixedData(data);

    OpenSshCertificateBuffer buffer = new OpenSshCertificateBuffer(bufferData);
    byte[] result = buffer.getBytes();

    assertArrayEquals(data, result);
  }

  /**
   * Tests that multiple sequential {@code getBytes()} calls work correctly.
   *
   * <p>
   * OpenSSH certificates contain multiple length-prefixed fields. This test verifies that the
   * buffer correctly advances its read position after each call, allowing sequential fields to be
   * read independently.
   * </p>
   */
  @Test
  void getBytes_multipleReads_worksCorrectly() {
    // Create buffer with two length-prefixed arrays
    byte[] data1 = {0x01, 0x02};
    byte[] data2 = {0x03, 0x04, 0x05};
    byte[] prefixed1 = createLengthPrefixedData(data1);
    byte[] prefixed2 = createLengthPrefixedData(data2);

    byte[] combined = new byte[prefixed1.length + prefixed2.length];
    System.arraycopy(prefixed1, 0, combined, 0, prefixed1.length);
    System.arraycopy(prefixed2, 0, combined, prefixed1.length, prefixed2.length);

    OpenSshCertificateBuffer buffer = new OpenSshCertificateBuffer(combined);

    byte[] result1 = buffer.getBytes();
    byte[] result2 = buffer.getBytes();

    assertArrayEquals(data1, result1);
    assertArrayEquals(data2, result2);
  }
}
