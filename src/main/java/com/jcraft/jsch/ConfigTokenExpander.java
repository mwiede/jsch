package com.jcraft.jsch;

import java.io.File;
import java.util.function.Function;

/** Expands OpenSSH-style percent tokens and environment variables in config paths. */
final class ConfigTokenExpander {
  private ConfigTokenExpander() {}

  /**
   * Expands a leading {@code ~} like OpenSSH, before tokens and environment variables, so a
   * substituted value is never home-expanded. Only the current user's home is known, so
   * {@code ~otheruser} is left as is.
   */
  static String expandPath(String path, Function<Character, String> tokens) throws JSchException {
    int rest = homePrefixLength(path);
    if (rest < 0) {
      return expand(path, tokens, true, false);
    }
    return Util.getSystemProperty("user.home") + expand(path.substring(rest), tokens, true, false);
  }

  static String expandTokens(String value, Function<Character, String> tokens)
      throws JSchException {
    return expand(value, tokens, false, false);
  }

  /** Expands the tokens {@code tokens} knows and keeps every other character sequence as is. */
  static String expandKnownTokens(String value, Function<Character, String> tokens) {
    try {
      return expand(value, tokens, false, true);
    } catch (JSchException e) {
      throw new IllegalStateException(e); // lenient expansion does not throw
    }
  }

  /** Returns the index after a leading "~", "~/", "~\" (Windows) or "~currentuser", else -1. */
  private static int homePrefixLength(String path) {
    if (!path.startsWith("~")) {
      return -1;
    }
    int end = 1;
    while (end < path.length() && !isSeparator(path.charAt(end))) {
      end++;
    }
    if (end == 1) {
      return 1;
    }
    String user = Util.getSystemProperty("user.name");
    return path.substring(1, end).equals(user) ? end : -1;
  }

  private static boolean isSeparator(char ch) {
    return ch == '/' || (File.separatorChar == '\\' && ch == '\\');
  }

  private static String expand(String path, Function<Character, String> tokens, boolean environment,
      boolean lenient) throws JSchException {
    StringBuilder expanded = new StringBuilder();
    int i = 0;
    while (i < path.length()) {
      char ch = path.charAt(i);
      if (ch == '%') {
        i = appendToken(path, i, tokens, lenient, expanded);
      } else if (environment && path.startsWith("${", i)) {
        i = appendEnvironment(path, i, expanded);
      } else {
        expanded.append(ch);
        i++;
      }
    }
    return expanded.toString();
  }

  /** Appends the value of the token starting at {@code percent}; returns the index after it. */
  private static int appendToken(String path, int percent, Function<Character, String> tokens,
      boolean lenient, StringBuilder expanded) throws JSchException {
    if (percent + 1 == path.length()) {
      if (!lenient) {
        throw new JSchException("Incomplete config path token: " + path);
      }
      expanded.append('%');
      return percent + 1;
    }
    char token = path.charAt(percent + 1);
    String value = token == '%' ? "%" : tokens.apply(token);
    if (value != null) {
      expanded.append(value);
    } else if (lenient) {
      expanded.append('%').append(token);
    } else {
      throw new JSchException("Unsupported config path token %" + token);
    }
    return percent + 2;
  }

  /**
   * Appends the variable starting at {@code start} ({@code ${NAME}}); returns the index after it.
   */
  private static int appendEnvironment(String path, int start, StringBuilder expanded)
      throws JSchException {
    int end = path.indexOf('}', start + 2);
    if (end < 0) {
      throw new JSchException("Incomplete config path environment variable: " + path);
    }
    String name = path.substring(start + 2, end);
    String value = Util.getSystemEnv(name);
    if (value == null) {
      throw new JSchException("Undefined config path environment variable: " + name);
    }
    expanded.append(value);
    return end + 1;
  }
}
