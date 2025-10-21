package com.jcraft.jsch;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

public class HostKeyTest {

  // Helper method to create a simple HostKey for testing
  private HostKey createHostKey(String hostPattern) throws Exception {
    // Create a dummy RSA key (just needs valid Base64 for the test)
    String dummyKey = "AAAAB3NzaC1yc2EAAAADAQABAAABAQ==";
    byte[] keyBytes = Util.fromBase64(Util.str2byte(dummyKey), 0, dummyKey.length());
    return new HostKey(hostPattern, HostKey.SSHRSA, keyBytes);
  }

  // ==================== Basic wildcard tests ====================

  @Test
  public void testIsWildcardMatched_exactMatch() throws Exception {
    HostKey hostKey = createHostKey("example.com");
    assertTrue(hostKey.isWildcardMatched("example.com"), "Should match exact hostname");
  }

  @Test
  public void testIsWildcardMatched_noMatch() throws Exception {
    HostKey hostKey = createHostKey("example.com");
    assertFalse(hostKey.isWildcardMatched("different.com"), "Should not match different hostname");
  }

  @Test
  public void testIsWildcardMatched_nullHostname() throws Exception {
    HostKey hostKey = createHostKey("example.com");
    assertFalse(hostKey.isWildcardMatched(null), "Should return false for null hostname");
  }

  // ==================== Single asterisk (*) wildcard tests ====================

  @Test
  public void testIsWildcardMatched_asteriskPrefix() throws Exception {
    HostKey hostKey = createHostKey("*.example.com");
    assertTrue(hostKey.isWildcardMatched("host.example.com"),
        "Should match *.example.com with host.example.com");
    assertTrue(hostKey.isWildcardMatched("sub.example.com"),
        "Should match *.example.com with sub.example.com");
    assertTrue(hostKey.isWildcardMatched("a.example.com"),
        "Should match *.example.com with a.example.com");
  }

  @Test
  public void testIsWildcardMatched_asteriskPrefixNoMatch() throws Exception {
    HostKey hostKey = createHostKey("*.example.com");
    assertFalse(hostKey.isWildcardMatched("example.com"),
        "Should not match *.example.com with example.com (no subdomain)");
    assertFalse(hostKey.isWildcardMatched("host.different.com"),
        "Should not match *.example.com with host.different.com");
  }

  @Test
  public void testIsWildcardMatched_asteriskSuffix() throws Exception {
    HostKey hostKey = createHostKey("192.168.1.*");
    assertTrue(hostKey.isWildcardMatched("192.168.1.1"),
        "Should match 192.168.1.* with 192.168.1.1");
    assertTrue(hostKey.isWildcardMatched("192.168.1.100"),
        "Should match 192.168.1.* with 192.168.1.100");
    assertTrue(hostKey.isWildcardMatched("192.168.1.254"),
        "Should match 192.168.1.* with 192.168.1.254");
  }

  @Test
  public void testIsWildcardMatched_asteriskSuffixNoMatch() throws Exception {
    HostKey hostKey = createHostKey("192.168.1.*");
    assertFalse(hostKey.isWildcardMatched("192.168.2.1"),
        "Should not match 192.168.1.* with 192.168.2.1");
    assertFalse(hostKey.isWildcardMatched("192.168.1"),
        "Should not match 192.168.1.* with 192.168.1 (incomplete)");
  }

  @Test
  public void testIsWildcardMatched_asteriskMiddle() throws Exception {
    HostKey hostKey = createHostKey("host-*.example.com");
    assertTrue(hostKey.isWildcardMatched("host-1.example.com"),
        "Should match host-*.example.com with host-1.example.com");
    assertTrue(hostKey.isWildcardMatched("host-prod.example.com"),
        "Should match host-*.example.com with host-prod.example.com");
  }

  @Test
  public void testIsWildcardMatched_multipleAsterisks() throws Exception {
    HostKey hostKey = createHostKey("*.*.example.com");
    assertTrue(hostKey.isWildcardMatched("sub.host.example.com"),
        "Should match *.*.example.com with sub.host.example.com");
    assertTrue(hostKey.isWildcardMatched("a.b.example.com"),
        "Should match *.*.example.com with a.b.example.com");
  }

  @Test
  public void testIsWildcardMatched_asteriskMatchesEmpty() throws Exception {
    HostKey hostKey = createHostKey("host*.example.com");
    assertTrue(hostKey.isWildcardMatched("host.example.com"),
        "Should match host*.example.com with host.example.com (* matches empty string)");
    assertTrue(hostKey.isWildcardMatched("host123.example.com"),
        "Should match host*.example.com with host123.example.com");
  }

  @Test
  public void testIsWildcardMatched_asteriskOnly() throws Exception {
    HostKey hostKey = createHostKey("*");
    assertTrue(hostKey.isWildcardMatched("anything.com"), "Should match * with anything.com");
    assertTrue(hostKey.isWildcardMatched("192.168.1.1"), "Should match * with 192.168.1.1");
    assertTrue(hostKey.isWildcardMatched("host"), "Should match * with host");
  }

  // ==================== Question mark (?) wildcard tests ====================

  @Test
  public void testIsWildcardMatched_questionMarkSingle() throws Exception {
    HostKey hostKey = createHostKey("host?.example.com");
    assertTrue(hostKey.isWildcardMatched("host1.example.com"),
        "Should match host?.example.com with host1.example.com");
    assertTrue(hostKey.isWildcardMatched("hosta.example.com"),
        "Should match host?.example.com with hosta.example.com");
    assertTrue(hostKey.isWildcardMatched("host-.example.com"),
        "Should match host?.example.com with host-.example.com");
  }

  @Test
  public void testIsWildcardMatched_questionMarkNoMatch() throws Exception {
    HostKey hostKey = createHostKey("host?.example.com");
    assertFalse(hostKey.isWildcardMatched("host.example.com"),
        "Should not match host?.example.com with host.example.com (missing character)");
    assertFalse(hostKey.isWildcardMatched("host12.example.com"),
        "Should not match host?.example.com with host12.example.com (too many characters)");
  }

  @Test
  public void testIsWildcardMatched_multipleQuestionMarks() throws Exception {
    HostKey hostKey = createHostKey("host-???.example.com");
    assertTrue(hostKey.isWildcardMatched("host-001.example.com"),
        "Should match host-???.example.com with host-001.example.com");
    assertTrue(hostKey.isWildcardMatched("host-abc.example.com"),
        "Should match host-???.example.com with host-abc.example.com");
    assertFalse(hostKey.isWildcardMatched("host-12.example.com"),
        "Should not match host-???.example.com with host-12.example.com (too few characters)");
  }

  // ==================== Mixed wildcard tests ====================

  @Test
  public void testIsWildcardMatched_mixedWildcards() throws Exception {
    HostKey hostKey = createHostKey("host-?-*.example.com");
    assertTrue(hostKey.isWildcardMatched("host-1-prod.example.com"),
        "Should match host-?-*.example.com with host-1-prod.example.com");
    assertTrue(hostKey.isWildcardMatched("host-a-test.example.com"),
        "Should match host-?-*.example.com with host-a-test.example.com");
  }

  // ==================== Comma-separated patterns ====================

  @Test
  public void testIsWildcardMatched_commaSeparatedFirstMatches() throws Exception {
    HostKey hostKey = createHostKey("host1.com,host2.com,host3.com");
    assertTrue(hostKey.isWildcardMatched("host1.com"),
        "Should match first pattern in comma-separated list");
  }

  @Test
  public void testIsWildcardMatched_commaSeparatedMiddleMatches() throws Exception {
    HostKey hostKey = createHostKey("host1.com,host2.com,host3.com");
    assertTrue(hostKey.isWildcardMatched("host2.com"),
        "Should match middle pattern in comma-separated list");
  }

  @Test
  public void testIsWildcardMatched_commaSeparatedLastMatches() throws Exception {
    HostKey hostKey = createHostKey("host1.com,host2.com,host3.com");
    assertTrue(hostKey.isWildcardMatched("host3.com"),
        "Should match last pattern in comma-separated list");
  }

  @Test
  public void testIsWildcardMatched_commaSeparatedNoMatch() throws Exception {
    HostKey hostKey = createHostKey("host1.com,host2.com,host3.com");
    assertFalse(hostKey.isWildcardMatched("host4.com"),
        "Should not match when hostname doesn't match any pattern in list");
  }

  @Test
  public void testIsWildcardMatched_commaSeparatedWithWildcards() throws Exception {
    HostKey hostKey = createHostKey("*.prod.com,*.test.com,192.168.*");
    assertTrue(hostKey.isWildcardMatched("host.prod.com"),
        "Should match *.prod.com in comma-separated wildcard list");
    assertTrue(hostKey.isWildcardMatched("server.test.com"),
        "Should match *.test.com in comma-separated wildcard list");
    assertTrue(hostKey.isWildcardMatched("192.168.1.1"),
        "Should match 192.168.* in comma-separated wildcard list");
    assertFalse(hostKey.isWildcardMatched("host.dev.com"),
        "Should not match when hostname doesn't match any wildcard pattern");
  }

  @Test
  public void testIsWildcardMatched_commaSeparatedWithSpaces() throws Exception {
    HostKey hostKey = createHostKey("host1.com, host2.com , host3.com");
    assertTrue(hostKey.isWildcardMatched("host1.com"), "Should handle spaces after comma");
    assertTrue(hostKey.isWildcardMatched("host2.com"), "Should handle spaces around comma");
    assertTrue(hostKey.isWildcardMatched("host3.com"), "Should handle leading space in pattern");
  }

  // ==================== Edge cases ====================

  @Test
  public void testIsWildcardMatched_emptyPattern() throws Exception {
    HostKey hostKey = createHostKey("");
    assertFalse(hostKey.isWildcardMatched("host.com"), "Should not match empty pattern");
  }

  @Test
  public void testIsWildcardMatched_emptyHostname() throws Exception {
    HostKey hostKey = createHostKey("host.com");
    assertFalse(hostKey.isWildcardMatched(""), "Should not match empty hostname");
  }

  @Test
  public void testIsWildcardMatched_caseSensitive() throws Exception {
    HostKey hostKey = createHostKey("Host.Example.COM");
    // OpenSSH wildcard matching is case-sensitive
    assertFalse(hostKey.isWildcardMatched("host.example.com"),
        "Wildcard matching should be case-sensitive");
    assertTrue(hostKey.isWildcardMatched("Host.Example.COM"), "Should match exact case");
  }

  @Test
  public void testIsWildcardMatched_specialCharacters() throws Exception {
    HostKey hostKey = createHostKey("host-1_2.example.com");
    assertTrue(hostKey.isWildcardMatched("host-1_2.example.com"),
        "Should match special characters in hostname");
  }

  // ==================== Real-world scenarios ====================

  @Test
  public void testIsWildcardMatched_wildcardSubdomain() throws Exception {
    HostKey hostKey = createHostKey("*.corp.example.com");
    assertTrue(hostKey.isWildcardMatched("server.corp.example.com"),
        "Should match subdomain with wildcard");
    assertTrue(hostKey.isWildcardMatched("db.corp.example.com"),
        "Should match different subdomain with wildcard");
    assertFalse(hostKey.isWildcardMatched("corp.example.com"),
        "Should not match base domain without subdomain");
  }

  @Test
  public void testIsWildcardMatched_ipv4Range() throws Exception {
    HostKey hostKey = createHostKey("10.0.0.*");
    assertTrue(hostKey.isWildcardMatched("10.0.0.1"), "Should match IP in range");
    assertTrue(hostKey.isWildcardMatched("10.0.0.255"), "Should match last IP in range");
    assertFalse(hostKey.isWildcardMatched("10.0.1.1"), "Should not match IP outside range");
  }

  @Test
  public void testIsWildcardMatched_hostnameWithPort() throws Exception {
    HostKey hostKey = createHostKey("[*.example.com]:2222");
    assertTrue(hostKey.isWildcardMatched("[host.example.com]:2222"),
        "Should match hostname with port and wildcard");
    assertFalse(hostKey.isWildcardMatched("[host.example.com]:22"),
        "Should not match different port");
  }
}
