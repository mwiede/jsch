package com.jcraft.jsch;

import java.net.InetAddress;
import java.net.UnknownHostException;

/** Local values for OpenSSH config tokens that Java exposes only indirectly. */
final class LocalIdentity {
  private LocalIdentity() {}

  /** The local host name ({@code %l}), or null if it cannot be determined. */
  static String hostname() {
    try {
      return InetAddress.getLocalHost().getHostName();
    } catch (UnknownHostException | SecurityException e) {
      return null;
    }
  }

  /** The numeric local user id ({@code %i}), or null where Java cannot tell, e.g. on Windows. */
  static String uid() {
    try {
      Class<?> unixSystem = Class.forName("com.sun.security.auth.module.UnixSystem");
      Object system = unixSystem.getDeclaredConstructor().newInstance();
      return String.valueOf(unixSystem.getMethod("getUid").invoke(system));
    } catch (ReflectiveOperationException | LinkageError | RuntimeException e) {
      return null;
    }
  }
}
