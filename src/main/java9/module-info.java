module com.jcraft.jsch {
    exports com.jcraft.jsch;

    requires java.security.jgss;
    requires static org.bouncycastle.provider;
    requires static org.newsclub.net.unix;
    requires static com.kohlschutter.junixsocket.nativecommon;
    requires static com.sun.jna;
    requires static com.sun.jna.platform;
}
