package com.jcraft.jsch.jgss;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.jcraft.jsch.JSchException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class GSSContextKrb5Test {

  private static final String USE_SUBJECT_CREDS_ONLY = "javax.security.auth.useSubjectCredsOnly";
  private static final String KRB5_CONFIG = "java.security.krb5.conf";

  @TempDir
  static Path tempDir;

  private static String originalUseSubjectCredsOnly;
  private static String originalKrb5Config;
  private InputStream originalSystemIn;
  private String previousUseSubjectCredsOnly;

  @BeforeAll
  static void configureKerberos() throws IOException {
    originalUseSubjectCredsOnly = System.getProperty(USE_SUBJECT_CREDS_ONLY);
    originalKrb5Config = System.getProperty(KRB5_CONFIG);
    Path config = tempDir.resolve("krb5.conf");
    String contents = "[libdefaults]\n" + "    default_realm = EXAMPLE.TEST\n"
        + "    dns_lookup_kdc = false\n" + "    dns_lookup_realm = false\n" + "    rdns = false\n"
        + "    udp_preference_limit = 1\n" + "    kdc_timeout = 1000\n" + "    max_retries = 1\n"
        + "[realms]\n" + "    EXAMPLE.TEST = {\n" + "        kdc = 127.0.0.1:1\n" + "    }\n";
    Files.write(config, contents.getBytes(StandardCharsets.UTF_8));
    System.setProperty(KRB5_CONFIG, config.toString());
  }

  @BeforeEach
  void prepareAttempt() {
    originalSystemIn = System.in;
    previousUseSubjectCredsOnly = System.getProperty(USE_SUBJECT_CREDS_ONLY);
    System.setIn(new ByteArrayInputStream(new byte[0]));
    System.clearProperty(USE_SUBJECT_CREDS_ONLY);
  }

  @AfterEach
  void restoreAttemptState() {
    try {
      restoreProperty(USE_SUBJECT_CREDS_ONLY, previousUseSubjectCredsOnly);
    } finally {
      System.setIn(originalSystemIn);
    }
  }

  @AfterAll
  static void restoreProperties() {
    try {
      restoreProperty(USE_SUBJECT_CREDS_ONLY, originalUseSubjectCredsOnly);
    } finally {
      restoreProperty(KRB5_CONFIG, originalKrb5Config);
    }
  }

  @Test
  void preservesUnsetPropertyAfterFailedAttempt() throws JSchException {
    attemptAuthentication();
    assertNull(System.getProperty(USE_SUBJECT_CREDS_ONLY));
  }

  @Test
  void preservesPropertySetAfterClassInitialization() throws JSchException {
    // Load the class with the property unset before simulating an application update.
    attemptAuthentication();
    System.setProperty(USE_SUBJECT_CREDS_ONLY, "false");
    attemptAuthentication();
    assertEquals("false", System.getProperty(USE_SUBJECT_CREDS_ONLY));
  }

  @Test
  void preservesExplicitTrueProperty() throws JSchException {
    System.setProperty(USE_SUBJECT_CREDS_ONLY, "true");
    attemptAuthentication();
    assertEquals("true", System.getProperty(USE_SUBJECT_CREDS_ONLY));
  }

  private static void attemptAuthentication() throws JSchException {
    GSSContextKrb5 context = new GSSContextKrb5();
    context.create("alice", "localhost");
    try {
      assertThrows(JSchException.class, () -> context.init(new byte[0], 0, 0));
    } finally {
      context.dispose();
    }
  }

  private static void restoreProperty(String name, String value) {
    if (value == null) {
      System.clearProperty(name);
    } else {
      System.setProperty(name, value);
    }
  }
}
