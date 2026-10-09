package com.jcraft.jsch;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class OpenSSHConfigTest {

  @TempDir
  Path tempDir;

  Map<String, String> keyMap = OpenSSHConfig.getKeymap().entrySet().stream().collect(Collectors
      .toMap(entry -> entry.getValue().toUpperCase(Locale.ROOT), Map.Entry::getKey, (s, s2) -> s2));

  @Test
  void parseFile() throws IOException, URISyntaxException {
    final String configFile =
        Paths.get(ClassLoader.getSystemResource("config").toURI()).toFile().getAbsolutePath();
    final OpenSSHConfig openSSHConfig = OpenSSHConfig.parseFile(configFile);
    final ConfigRepository.Config config = openSSHConfig.getConfig("host2");
    assertNotNull(config);
    assertEquals("foobar", config.getUser());
    assertEquals("host2.somewhere.edu", config.getHostname());
    assertEquals("~/.ssh/old_keys/host2_key", config.getValue("IdentityFile"));
  }

  @Test
  void includesGlobsInLexicalOrderAndRestoresHostScope() throws IOException {
    Path sshDir = Files.createDirectory(tempDir.resolve("ssh"));
    Path snippets = Files.createDirectory(sshDir.resolve("snippets"));
    write(snippets.resolve("20.conf"), "Host target\n  User second\n");
    write(snippets.resolve("10.conf"), "User first\nHost elsewhere\n  Port 2222\n");
    Path main = tempDir.resolve("config");
    write(main, "Host target\n  Include snippets/*.conf\n  HostName after.example\n");

    OpenSSHConfig config = OpenSSHConfig.parseFile(main.toString(), sshDir);
    assertEquals("first", config.getConfig("target").getUser());
    assertEquals("after.example", config.getConfig("target").getHostname());
    assertEquals(-1, config.getConfig("elsewhere").getPort());
  }

  @Test
  void nestedIncludeCannotEscapeEnclosingHost() throws IOException {
    Path nested = tempDir.resolve("nested.conf");
    Path middle = tempDir.resolve("middle.conf");
    write(nested, "Host other\n Port 2222\nHost target\n User nested\n");
    write(middle, "Include " + nested + "\n");
    Path main = tempDir.resolve("config");
    write(main, "Host target\n Include " + middle + "\n");

    OpenSSHConfig config = OpenSSHConfig.parseFile(main.toString());
    assertEquals(-1, config.getConfig("other").getPort());
    assertEquals("nested", config.getConfig("target").getUser());
  }

  @Test
  void matchConditionsUseEffectiveHostAndRemoteUser() throws IOException {
    OpenSSHConfig config = OpenSSHConfig.parse(
        "Host alias\n HostName real.example\n" + "Match host real.example user deploy\n Port 2222\n"
            + "Match originalhost alias localuser " + System.getProperty("user.name")
            + "\n User matched\nMatch all\n ForwardAgent yes\n");

    assertEquals(2222, config.getConfig("alias", "deploy").getPort());
    assertEquals(-1, config.getConfig("alias", "other").getPort());
    assertEquals("matched", config.getConfig("alias").getUser());
    assertEquals("yes", config.getConfig("elsewhere").getValue("ForwardAgent"));
  }

  @Test
  void matchPatternListsUseCommasAndRespectNegation() throws IOException {
    OpenSSHConfig config = OpenSSHConfig.parse("Match !host bastion,jump\n"
        + " StrictHostKeyChecking no\nMatch host *.corp,!legacy.corp\n Port 2222\n");

    assertNull(config.getConfig("bastion").getValue("StrictHostKeyChecking"));
    assertNull(config.getConfig("jump").getValue("StrictHostKeyChecking"));
    assertEquals("no", config.getConfig("other").getValue("StrictHostKeyChecking"));
    assertEquals(2222, config.getConfig("new.corp").getPort());
    assertEquals(-1, config.getConfig("legacy.corp").getPort());
  }

  @Test
  void enclosingMatchIsEvaluatedOnceBeforeIncludedHostNameChanges() throws IOException {
    Path child = tempDir.resolve("child.conf");
    write(child, "HostName real.example\nHost *\n Port 2222\n");
    Path main = tempDir.resolve("config");
    write(main, "Match host alias\n Include " + child + "\n");

    assertEquals(2222, OpenSSHConfig.parseFile(main.toString()).getConfig("alias").getPort());
  }

  @Test
  void matchHostUsesTheSameLiteralPercentExpansionAsSession() throws Exception {
    JSch jsch = new JSch();
    jsch.setConfigRepository(
        OpenSSHConfig.parse("Host alias\n HostName a%%h\n" + "Match host a%h\n Port 2222\n"));

    assertEquals(2222, jsch.getSession("alias").getPort());
    assertEquals("a%h", jsch.getSession("alias").getHost());
  }

  @Test
  void channelUsesOriginalMatchUserEvaluation() throws Exception {
    String remoteUser = "jsch-match-remote-user";
    JSch jsch = new JSch();
    jsch.setConfigRepository(OpenSSHConfig.parse(
        "Match user " + remoteUser + "\n ForwardAgent yes\nHost prod\n User " + remoteUser + "\n"));

    Session inferredUser = jsch.getSession("prod");
    ChannelExec inferredChannel = new ChannelExec();
    inferredUser.applyConfigChannel(inferredChannel);
    assertFalse(inferredChannel.agent_forwarding);

    Session explicitUser = jsch.getSession(remoteUser, "prod");
    ChannelExec explicitChannel = new ChannelExec();
    explicitUser.applyConfigChannel(explicitChannel);
    assertTrue(explicitChannel.agent_forwarding);
  }

  @Test
  void bareScopeDirectivesFailInsteadOfLeakingPreviousScope() {
    assertThrows(IOException.class, () -> OpenSSHConfig.parse("Host target\nMatch\n Port 2222\n"));
    assertThrows(IOException.class, () -> OpenSSHConfig.parse("Host target\nInclude\n"));
    assertThrows(IOException.class, () -> OpenSSHConfig.parse("Host\n"));
  }

  @Test
  void sessionPassesExplicitUserToMatch() throws Exception {
    JSch jsch = new JSch();
    jsch.setConfigRepository(
        OpenSSHConfig.parse("Match user deploy\n Port 2222\nMatch all\n User configured\n"));

    assertEquals(2222, jsch.getSession("deploy", "example.com").getPort());
    assertEquals(22, jsch.getSession("other", "example.com").getPort());
  }

  @Test
  void includedMatchCannotEscapeEnclosingHost() throws IOException {
    Path included = tempDir.resolve("child.conf");
    write(included, "Match all\n Port 2222\n");
    Path main = tempDir.resolve("config");
    write(main, "Host alias\n Include " + included + "\n");

    OpenSSHConfig config = OpenSSHConfig.parseFile(main.toString());
    assertEquals(2222, config.getConfig("alias").getPort());
    assertEquals(-1, config.getConfig("elsewhere").getPort());
  }

  @Test
  void unsupportedMatchConditionFailsClosed() {
    assertThrows(IOException.class,
        () -> OpenSSHConfig.parse("Match exec true\n StrictHostKeyChecking no\n"));
  }

  @Test
  void includeGlobsSkipDotfiles() throws IOException {
    Path snippets = Files.createDirectory(tempDir.resolve("snippets"));
    write(snippets.resolve(".hidden.conf"), "User hidden\n");
    write(snippets.resolve("visible.conf"), "User visible\n");
    Path main = tempDir.resolve("config");
    write(main, "Include " + snippets + "/*.conf\n");
    assertEquals("visible", OpenSSHConfig.parseFile(main.toString()).getConfig("any").getUser());
  }

  @Test
  void includeExpandsHomeToken() throws IOException {
    Path main = tempDir.resolve("config");
    Path included = tempDir.resolve("included.conf");
    String originalHome = System.getProperty("user.home");
    try {
      System.setProperty("user.home", tempDir.toString());
      write(included, "Host target\n User from-home\n");
      write(main, "Include %d/" + included.getFileName() + "\n");
      assertEquals("from-home",
          OpenSSHConfig.parseFile(main.toString()).getConfig("target").getUser());
    } finally {
      System.setProperty("user.home", originalHome);
    }
  }

  @Test
  void includeExpandsLiteralPercent() throws IOException {
    Path included = tempDir.resolve("%literal.conf");
    write(included, "Host target\n User included\n");
    Path main = tempDir.resolve("config");
    write(main, "Include %%literal.conf\n");

    assertEquals("included",
        OpenSSHConfig.parseFile(main.toString(), tempDir).getConfig("target").getUser());
  }

  @Test
  void unsetIncludeEnvironmentVariableReportsError() throws IOException {
    Path main = tempDir.resolve("config");
    write(main, "Include ${JSCH_UNSET_INCLUDE_TEST_90748}/missing.conf\n");

    IOException error =
        assertThrows(IOException.class, () -> OpenSSHConfig.parseFile(main.toString(), tempDir));
    assertTrue(error.getCause().getMessage().contains("JSCH_UNSET_INCLUDE_TEST_90748"));
  }

  @Test
  void includeArgumentPreservesUnrecognizedBackslashEscapes() throws IOException {
    Path main = tempDir.resolve("config");
    write(main, "Include " + tempDir + "/missing\\name.conf\nHost target\n User someone\n");
    assertEquals("someone", OpenSSHConfig.parseFile(main.toString()).getConfig("target").getUser());
  }

  @Test
  void emptyHostPatternIsRejected() {
    assertThrows(IOException.class, () -> OpenSSHConfig.parse("Host =\n User someone\n"));
  }

  @Test
  void nestedIncludesAndQuotedPathsRetainFirstValue() throws IOException {
    Path nested = tempDir.resolve("nested file.conf");
    write(nested, "User nested\n");
    Path middle = tempDir.resolve("middle.conf");
    write(middle, "Include \"" + nested + "\"\nUser middle\n");
    Path main = tempDir.resolve("config");
    write(main, "Host target\n Include " + middle + "\n User outer\n");

    OpenSSHConfig config = OpenSSHConfig.parseFile(main.toString());
    assertEquals("nested", config.getConfig("target").getUser());
  }

  @Test
  void includeAcceptsMultiplePathsOnOneLine() throws IOException {
    Path first = tempDir.resolve("first.conf");
    Path second = tempDir.resolve("second.conf");
    write(first, "Host target\n User from-first\n");
    write(second, "Host target\n Port 2200\n");
    Path main = tempDir.resolve("config");
    write(main, "Include = " + first + " " + second + "\n");

    OpenSSHConfig config = OpenSSHConfig.parseFile(main.toString());
    assertEquals("from-first", config.getConfig("target").getUser());
    assertEquals(2200, config.getConfig("target").getPort());
  }

  @Test
  void unsupportedIncludeTokenIsRejected() throws IOException {
    Path main = tempDir.resolve("config");
    write(main, "Include %h/something.conf\n");
    assertThrows(IOException.class, () -> OpenSSHConfig.parseFile(main.toString()));
  }

  @Test
  void repeatedHostBlocksDoNotOverwriteEachOther() throws IOException {
    OpenSSHConfig config = OpenSSHConfig
        .parse("Host target\n User first\nHost target\n HostName destination\n User second\n");
    assertEquals("first", config.getConfig("target").getUser());
    assertEquals("destination", config.getConfig("target").getHostname());
  }

  @Test
  void missingIncludeIsIgnoredAndCycleIsRejected() throws IOException {
    Path main = tempDir.resolve("config");
    write(main, "Include missing/*.conf\nHost target\n User someone\n");
    assertEquals("someone", OpenSSHConfig.parseFile(main.toString()).getConfig("target").getUser());

    write(main, "Include " + main + "\n");
    assertThrows(IOException.class, () -> OpenSSHConfig.parseFile(main.toString()));
  }

  @ParameterizedTest
  @ValueSource(strings = {"MACs", "Macs"})
  void parseMacsCaseInsensitive(String key) throws IOException {
    OpenSSHConfig parse = OpenSSHConfig.parse(key + " someValue");
    ConfigRepository.Config config = parse.getConfig("");
    assertEquals("someValue", config.getValue("mac.c2s"));
    assertEquals("someValue", config.getValue("mac.s2c"));
  }

  @Test
  void appendKexAlgorithms() throws IOException {
    OpenSSHConfig parse = OpenSSHConfig.parse("KexAlgorithms +diffie-hellman-group1-sha1");
    ConfigRepository.Config kex = parse.getConfig("");
    assertEquals(JSch.getConfig("kex") + "," + "diffie-hellman-group1-sha1", kex.getValue("kex"));
  }

  @ParameterizedTest
  @ValueSource(strings = {"KexAlgorithms", "Ciphers", "HostKeyAlgorithms", "MACs",
      "PubkeyAcceptedAlgorithms", "PubkeyAcceptedKeyTypes"})
  void appendAlgorithms(String key) throws IOException {
    OpenSSHConfig parse = OpenSSHConfig.parse(key + " +someValue,someValue1");
    ConfigRepository.Config config = parse.getConfig("");
    String mappedKey = Optional.ofNullable(keyMap.get(key.toUpperCase(Locale.ROOT))).orElse(key);
    assertEquals(JSch.getConfig(mappedKey) + "," + "someValue,someValue1",
        config.getValue(mappedKey));
  }

  @ParameterizedTest
  @ValueSource(strings = {"KexAlgorithms", "Ciphers", "HostKeyAlgorithms", "MACs",
      "PubkeyAcceptedAlgorithms", "PubkeyAcceptedKeyTypes"})
  void prependAlgorithms(String key) throws IOException {
    OpenSSHConfig parse = OpenSSHConfig.parse(key + " ^someValue,someValue1");
    ConfigRepository.Config config = parse.getConfig("");
    String mappedKey = Optional.ofNullable(keyMap.get(key.toUpperCase(Locale.ROOT))).orElse(key);
    assertEquals("someValue,someValue1," + JSch.getConfig(mappedKey), config.getValue(mappedKey));
  }

  @Test
  void prependKexAlgorithms() throws IOException {
    OpenSSHConfig parse = OpenSSHConfig.parse("KexAlgorithms ^diffie-hellman-group1-sha1");
    ConfigRepository.Config kex = parse.getConfig("");
    assertEquals("diffie-hellman-group1-sha1," + JSch.getConfig("kex"), kex.getValue("kex"));
  }

  @Test
  void removeKexAlgorithm() throws IOException {
    OpenSSHConfig parse = OpenSSHConfig.parse("KexAlgorithms -ecdh-sha2-nistp256");
    ConfigRepository.Config kex = parse.getConfig("");
    assertEquals(JSch.getConfig("kex").replaceAll(",ecdh-sha2-nistp256", ""), kex.getValue("kex"));
  }

  @Test
  void replaceKexAlgorithms() throws IOException {
    OpenSSHConfig parse = OpenSSHConfig.parse("KexAlgorithms diffie-hellman-group1-sha1");
    ConfigRepository.Config kex = parse.getConfig("");
    assertEquals("diffie-hellman-group1-sha1", kex.getValue("kex"));
  }

  @Test
  void parseFileWithNegations() throws IOException, URISyntaxException {
    final String configFile =
        Paths.get(ClassLoader.getSystemResource("config_with_negations").toURI()).toFile()
            .getAbsolutePath();
    final OpenSSHConfig openSSHConfig = OpenSSHConfig.parseFile(configFile);

    assertUserEquals(openSSHConfig, "my.example.com", "u1");
    assertUserEquals(openSSHConfig, "my-jump.example.com", "jump-u1");
    assertUserEquals(openSSHConfig, "my-proxy.example.com", "proxy-u1");
    assertUserEquals(openSSHConfig, "my.example.org", "u2");
  }

  @ParameterizedTest
  @ValueSource(strings = {"ConnectTimeout", "ServerAliveInterval"})
  void timeoutsAreConvertedToMs(String configKey) throws IOException {
    OpenSSHConfig parse = OpenSSHConfig.parse(configKey + " 42");
    ConfigRepository.Config config = parse.getConfig("");
    assertEquals("42000", config.getValue(configKey));
  }

  private void assertUserEquals(OpenSSHConfig openSSHConfig, String host, String expected) {
    final ConfigRepository.Config config = openSSHConfig.getConfig(host);
    assertNotNull(config);
    String actual = config.getUser();
    assertEquals(expected, actual, String.format(Locale.ROOT,
        "Expected user for host %s to be %s, but was %s", host, expected, actual));
  }

  private static void write(Path path, String value) throws IOException {
    Files.write(path, value.getBytes(StandardCharsets.UTF_8));
  }

  @Test
  void matchFinalRunsSecondPassAgainstResolvedHostLikeOpenSsh() throws IOException {
    // Checked against OpenSSH 10.0 ssh -G.
    OpenSSHConfig config = OpenSSHConfig.parse(
        String.join("\n", "Host alias", "  HostName real.example", "Match final", "  Port 1111",
            "Host alias", "  User aliasuser", "Host real.example", "  ConnectTimeout 7", ""));
    ConfigRepository.Config alias = config.getConfig("alias");
    assertEquals("aliasuser", alias.getUser());
    assertEquals(1111, alias.getPort());
    assertEquals("7000", alias.getValue("ConnectTimeout"));

    config = OpenSSHConfig.parse(
        String.join("\n", "Match final host alias", "  User a", "Match final host real.example",
            "  Port 2222", "Host alias", "  HostName real.example", ""));
    assertNull(config.getConfig("alias").getUser());
    assertEquals(2222, config.getConfig("alias").getPort());

    config = OpenSSHConfig.parse("Match final\n  Port 1\nHost alias\n  Port 2\n");
    assertEquals(2, config.getConfig("alias").getPort());
    config = OpenSSHConfig.parse("Match !final\n  User first\n");
    assertEquals("first", config.getConfig("alias").getUser());
    config = OpenSSHConfig.parse("Match final all\n  User fin\n");
    assertEquals("fin", config.getConfig("alias").getUser());
    assertThrows(IOException.class, () -> OpenSSHConfig.parse("Match all final\n  User x\n"));
  }

  @Test
  void finalPassKeepsIdentityFileOrder() throws IOException {
    OpenSSHConfig config = OpenSSHConfig.parse(String.join("\n", "Host *", "  IdentityFile a",
        "Host alias", "  IdentityFile b", "Match final", "  IdentityFile c", ""));
    assertEquals(Arrays.asList("a", "b", "c"),
        Arrays.asList(config.getConfig("alias").getValues("IdentityFile")));
  }

  @Test
  void matchCanonicalNeedsCanonicalizeHostname() throws IOException {
    assertEquals(-1,
        OpenSSHConfig.parse("Match canonical\n  Port 5\n").getConfig("alias").getPort());
    assertEquals(6, OpenSSHConfig.parse("CanonicalizeHostname yes\nMatch canonical\n  Port 6\n")
        .getConfig("alias").getPort());
  }

  @Test
  void matchTaggedSeesTagSetEarlier() throws IOException {
    assertEquals(7,
        OpenSSHConfig.parse("Tag foo\nMatch tagged foo\n  Port 7\n").getConfig("alias").getPort());
    assertEquals(8,
        OpenSSHConfig.parse("Match tagged \"\"\n  Port 8\n").getConfig("alias").getPort());
    assertEquals(-1, OpenSSHConfig.parse("Match tagged foo\n  Port 9\nHost *\n  Tag foo\n")
        .getConfig("alias").getPort());
    assertEquals(10, OpenSSHConfig.parse("Tag prod-eu\nMatch tagged prod-*,!prod-us\n  Port 10\n")
        .getConfig("alias").getPort());
  }

  @Test
  void matchVersionUsesJSchVersion() throws IOException {
    assertEquals(11,
        OpenSSHConfig.parse("Match version JSCH_*\n  Port 11\n").getConfig("alias").getPort());
    assertEquals(-1,
        OpenSSHConfig.parse("Match version OpenSSH_*\n  Port 12\n").getConfig("alias").getPort());
  }

  @Test
  void matchLocalNetworkChecksInterfacesWithoutResolvingNames() throws IOException {
    assertEquals(13,
        OpenSSHConfig.parse("Match localnetwork 192.0.2.0/24,127.0.0.0/8,::1\n" + "  Port 13\n")
            .getConfig("alias").getPort());
    assertEquals(13, OpenSSHConfig.parse("Match localnetwork 127.0.0.0/0008\n  Port 13\n")
        .getConfig("alias").getPort(), "a zero-padded prefix length is a number");
    assertEquals(-1, OpenSSHConfig.parse("Match localnetwork 192.0.2.0/24\n  Port 14\n")
        .getConfig("alias").getPort());
    for (String list : new String[] {"127.0.0.1/8", "localhost", "!10.0.0.0/8", "10.0.0.0/33",
        "256.1.1.1/32", "10.0.0.0/+8", "10.0.0.0/ 8", "010.0.0.0/8", "fe80::1%eth0", ""}) {
      assertThrows(IOException.class,
          () -> OpenSSHConfig.parse("Match localnetwork \"" + list + "\"\n  Port 1\n"), list);
    }
  }

  @Test
  void matchCriteriaJSchCannotEvaluateFailClosed() throws IOException {
    IOException exec = assertThrows(IOException.class,
        () -> OpenSSHConfig.parse("Host a\n  Port 2\nMatch exec true\n  Port 1\n"));
    assertTrue(exec.getMessage().startsWith("ssh config:3: Unsupported Match criterion: exec"),
        exec.getMessage());
    assertTrue(exec.getMessage().contains("never runs commands"), exec.getMessage());

    Path included = tempDir.resolve("exec.conf");
    Files.write(included, "Host b\nMatch exec true\n".getBytes(StandardCharsets.UTF_8));
    Path main = tempDir.resolve("main.conf");
    Files.write(main, ("Host a\nInclude " + included + "\n").getBytes(StandardCharsets.UTF_8));
    IOException fromInclude =
        assertThrows(IOException.class, () -> OpenSSHConfig.parseFile(main.toString()));
    assertTrue(fromInclude.getMessage().startsWith(main + ":2: " + included + ":2: "),
        "names the include line and the offending line: " + fromInclude.getMessage());
    for (String criterion : new String[] {"command ls", "sessiontype shell", "bogus x"}) {
      assertThrows(IOException.class,
          () -> OpenSSHConfig.parse("Match " + criterion + "\n  Port 1\n"), criterion);
    }
  }

  @Test
  void trailingCommentsAreIgnoredLikeOpenSsh() throws IOException {
    OpenSSHConfig config = OpenSSHConfig.parse(String.join("\n", "Host other # alias", "  Port 20",
        "Host alias", "  User bob # comment", "  HostName h#1", "  Port # none", ""));
    assertEquals(-1, config.getConfig("alias").getPort());
    assertEquals("bob", config.getConfig("alias").getUser());
    assertEquals("h#1", config.getConfig("alias").getHostname());
    assertEquals(20, config.getConfig("other").getPort());
  }

  @Test
  void includeExpandsCurrentUserHomeButRejectsOtherUsers() throws IOException {
    String originalHome = System.getProperty("user.home");
    try {
      System.setProperty("user.home", tempDir.toString());
      Files.write(tempDir.resolve("inc.conf"),
          "Host alias\n  Port 2345\n".getBytes(StandardCharsets.UTF_8));
      String user = System.getProperty("user.name");
      assertEquals(2345,
          OpenSSHConfig.parse("Include ~" + user + "/inc.conf\n").getConfig("alias").getPort());
      assertThrows(IOException.class,
          () -> OpenSSHConfig.parse("Include ~not-" + user + "/inc.conf\n"));
    } finally {
      System.setProperty("user.home", originalHome);
    }
  }

  @Test
  @org.junit.jupiter.api.condition.EnabledOnOs(org.junit.jupiter.api.condition.OS.WINDOWS)
  void includeAcceptsWindowsHomeSeparator() throws IOException {
    String originalHome = System.getProperty("user.home");
    try {
      System.setProperty("user.home", tempDir.toString());
      Files.write(tempDir.resolve("inc.conf"),
          "Host alias\n  Port 2346\n".getBytes(StandardCharsets.UTF_8));
      assertEquals(2346, OpenSSHConfig.parse("Include ~\\inc.conf\n").getConfig("alias").getPort());
    } finally {
      System.setProperty("user.home", originalHome);
    }
  }

  @Test
  void systemFileResolvesRelativeIncludesAgainstItsDirectory() throws IOException {
    Path etc = Files.createDirectories(tempDir.resolve("etc-ssh"));
    Files.createDirectories(etc.resolve("ssh_config.d"));
    Files.write(etc.resolve("ssh_config.d/10.conf"),
        "Host alias\n  Port 2347\n".getBytes(StandardCharsets.UTF_8));
    Path system = etc.resolve("ssh_config");
    Files.write(system, "Include ssh_config.d/*.conf\n".getBytes(StandardCharsets.UTF_8));
    assertEquals(2347,
        OpenSSHConfig.parseSystemFile(system.toString()).getConfig("alias").getPort());
  }
}
