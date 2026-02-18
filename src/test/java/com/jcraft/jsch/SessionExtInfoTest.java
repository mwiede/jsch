package com.jcraft.jsch;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Tests for the private Session.checkServerExtInfo(). We craft the internal
 * I_S (server KEXINIT payload) so that the method will parse the first name-list (kex algorithms)
 * starting at offset 17.
 */
public class SessionExtInfoTest {
    private static byte[] buildIS(String kexAlgorithmsNameList) {
        byte[] kexBytes = Util.str2byte(kexAlgorithmsNameList);
        int len = kexBytes.length;
        byte[] is = new byte[17 + 4 + len];
        // first 17 bytes remain 0 (arbitrary, not used by method)
        // write length (uint32, big endian)
        is[17] = (byte) (len >>> 24);
        is[18] = (byte) (len >>> 16);
        is[19] = (byte) (len >>> 8);
        is[20] = (byte) (len);
        System.arraycopy(kexBytes, 0, is, 21, len);
        return is;
    }

    private static Session newSession() throws Exception {
        // Reuse pattern from existing tests: username null -> defaults to system user.
        return new Session(new JSch(), null, null, 0);
    }

    @Test
    @DisplayName("checkServerExtInfo returns true when ext-info-s present")
    void extInfoPresent() throws Exception {
        Session s = newSession();
        s.I_S = buildIS("diffie-hellman-group1-sha1,ext-info-s,curve25519-sha256");
        assertTrue(s.checkServerExtInfo());
    }

    @Test
    @DisplayName("checkServerExtInfo returns false when ext-info-s absent")
    void extInfoAbsent() throws Exception {
        Session s = newSession();
        s.I_S = buildIS("diffie-hellman-group1-sha1,curve25519-sha256");
        assertFalse(s.checkServerExtInfo());
    }

    @Test
    @DisplayName("checkServerExtInfo handles consecutive commas (empty entries) without looping")
    void extInfoWithEmptyEntries() throws Exception {
        Session s = newSession();
        // Leading and consecutive commas introduce empty name-list elements.
        s.I_S = buildIS(",,ext-info-s,,diffie-hellman-group14-sha1,,");
        assertTrue(s.checkServerExtInfo());
    }

    @Test
    @DisplayName("checkServerExtInfo handles only empty entries and returns false")
    void extInfoOnlyEmptyEntries() throws Exception {
        Session s = newSession();
        s.I_S = buildIS(",,,"); // name-list of empty elements
        assertFalse(s.checkServerExtInfo());
    }
}
