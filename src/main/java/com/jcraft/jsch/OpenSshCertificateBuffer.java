package com.jcraft.jsch;

import java.nio.charset.Charset;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.Map;

import static com.jcraft.jsch.OpenSshCertificateUtil.*;
import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * A specialized buffer for parsing OpenSSH certificate data.
 *
 * <p>
 * This class extends the base {@link Buffer} class to provide additional methods specific to
 * parsing OpenSSH certificate format data structures, including string collections, key-value maps,
 * and certificate-specific data types.
 * </p>
 *
 * <p>
 * The buffer follows the SSH wire format protocol for data serialization, where strings and byte
 * arrays are prefixed with their length as a 32-bit integer.
 * </p>
 */
public class OpenSshCertificateBuffer extends Buffer {

  private static final byte[] EMPTY_BYTE_ARRAY = {};


  /**
   * Creates a new OpenSSH certificate buffer from decoded certificate bytes.
   *
   * @param certificateByteDecoded the decoded certificate data
   */
  public OpenSshCertificateBuffer(byte[] certificateByteDecoded) {
    super(certificateByteDecoded);
    s = 0;
    index = certificateByteDecoded.length;

  }

  /**
   * Reads a length-prefixed byte array from the buffer.
   *
   * @return the byte array data
   */
  public byte[] getBytes() {
    int reqLen = getInt();
    byte[] b = new byte[reqLen];
    getByte(b);
    return b;
  }

  /**
   * Reads a string with the specified character encoding.
   *
   * @param charset the character encoding to use
   * @return the decoded string
   */
  public String getString(Charset charset) {
    return new String(getString(), charset);
  }


  /**
   * Reads a collection of UTF-8 encoded strings from the buffer.
   *
   * <p>
   * This method reads all remaining data in the buffer and parses it as a sequence of
   * length-prefixed UTF-8 strings.
   * </p>
   *
   * @return collection of strings
   */
  public Collection<String> getStrings() {
    Collection<String> list = new LinkedList<>();
    while (getLength() > 0) {
      String s = getString(UTF_8);
      list.add(s);
    }
    return list;
  }

  /**
   * Reads critical options from the buffer.
   *
   * <p>
   * Critical options are stored as key-value pairs in SSH wire format.
   * </p>
   *
   * @return map of critical option names to values
   */
  public Map<String, String> getCriticalOptions() {
    return getKeyValueData();
  }

  /**
   * Reads extensions from the buffer.
   *
   * <p>
   * Extensions are stored as key-value pairs in SSH wire format.
   * </p>
   *
   * @return map of extension names to values
   */
  public Map<String, String> getExtensions() {
    return getKeyValueData();
  }

  /**
   * Reads key-value pair data from the buffer.
   *
   * <p>
   * This method handles the SSH wire format for storing maps, where the entire map is first stored
   * as a length-prefixed blob, followed by alternating keys and values, each also length-prefixed.
   * </p>
   *
   * @return map of keys to values
   */
  private Map<String, String> getKeyValueData() {
    Map<String, String> map = new LinkedHashMap<>();

    if (getLength() > 0) {
      OpenSshCertificateBuffer keyValueDataBuffer = new OpenSshCertificateBuffer(getString());
      while (keyValueDataBuffer.getLength() > 0) {
        String key = keyValueDataBuffer.getString(UTF_8);
        String value = keyValueDataBuffer.getString(UTF_8);
        map.put(key, value);
      }
    }
    return map;
  }

  /**
   * Writes a UTF-8 encoded string to the buffer with length prefix.
   *
   * @param string the strin
   */
  public void putString(String string) {
    if (isEmpty(string)) {
      putByte(EMPTY_BYTE_ARRAY);
    } else {
      byte[] stringBytes = string.getBytes(UTF_8);
      putInt(stringBytes.length);
      putByte(stringBytes);
    }
  }


  public int getReadPosition() {
    return s;
  }

  public int getWritePosition() {
    return index;
  }
}
