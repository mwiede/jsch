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
  void includeDoesNotExpandPercentTokens() throws IOException {
    Path main = tempDir.resolve("config");
    Path included = tempDir.resolve("%d.conf");
    write(included, "Host target\n User from-literal\n");
    write(main, "Include %d.conf\n");
    assertEquals("from-literal",
        OpenSSHConfig.parseFile(main.toString(), tempDir).getConfig("target").getUser());
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
  void unresolvedIncludeTokenIsNotAnError() throws IOException {
    Path main = tempDir.resolve("config");
    write(main, "Include %h/something.conf\nHost target\n User someone\n");
    assertEquals("someone", OpenSSHConfig.parseFile(main.toString()).getConfig("target").getUser());
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
  void trailingCommentsAreIgnoredLikeOpenSsh() throws IOException {
    OpenSSHConfig config = OpenSSHConfig.parse(String.join("\n", "Host other # alias", "  Port 20",
        "Host alias", "  User bob # comment", "  HostName h#1", "  Port # none", ""));
    assertEquals(-1, config.getConfig("alias").getPort());
    assertEquals("bob", config.getConfig("alias").getUser());
    assertEquals("h#1", config.getConfig("alias").getHostname());
    assertEquals(20, config.getConfig("other").getPort());
  }
}
