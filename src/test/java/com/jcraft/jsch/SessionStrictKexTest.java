package com.jcraft.jsch;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Tests for the private Session.checkServerStrictKex() method via reflection.
 * We craft the internal I_S (server KEXINIT payload) so that the method
 * will parse the first name-list (kex algorithms) starting at offset 17.
 */
class SessionStrictKexTest {

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

    private static boolean invokeCheck(Session session) throws Exception {
        Method m = Session.class.getDeclaredMethod("checkServerStrictKex");
        m.setAccessible(true);
        return (boolean) m.invoke(session);
    }

    private static void setIS(Session session, byte[] value) throws Exception {
        Field f = Session.class.getDeclaredField("I_S");
        f.setAccessible(true);
        f.set(session, value);
    }

    private static Session newSession() throws Exception {
        // Reuse pattern from existing tests: username null -> defaults to system user.
        return new Session(new JSch(), null, null, 0);
    }

    @Test
    @DisplayName("checkServerStrictKex returns true when target algo present")
    void strictKexPresent() throws Exception {
        Session s = newSession();
        setIS(s, buildIS("diffie-hellman-group1-sha1,kex-strict-s-v00@openssh.com,curve25519-sha256"));
        assertTrue(invokeCheck(s));
    }

    @Test
    @DisplayName("checkServerStrictKex returns false when target algo absent")
    void strictKexAbsent() throws Exception {
        Session s = newSession();
        setIS(s, buildIS("diffie-hellman-group1-sha1,curve25519-sha256"));
        assertFalse(invokeCheck(s));
    }

    @Test
    @DisplayName("checkServerStrictKex handles consecutive commas (empty entries) without looping")
    void strictKexWithEmptyEntries() throws Exception {
        Session s = newSession();
        // Leading and consecutive commas introduce empty name-list elements.
        setIS(s, buildIS(",,kex-strict-s-v00@openssh.com,,diffie-hellman-group14-sha1,,"));
        assertTrue(invokeCheck(s));
    }

    @Test
    @DisplayName("checkServerStrictKex handles only empty entries and returns false")
    void strictKexOnlyEmptyEntries() throws Exception {
        Session s = newSession();
        setIS(s, buildIS(",,,")); // name-list of empty elements
        assertFalse(invokeCheck(s));
    }
}