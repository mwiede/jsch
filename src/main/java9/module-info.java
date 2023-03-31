module com.jcraft.jsch {
    exports com.jcraft.jsch;

    requires static java.security.jgss;
    requires static java.logging;
    requires static org.apache.logging.log4j;
    requires static org.slf4j;
    requires static org.bouncycastle.provider;
    requires static org.newsclub.net.unix;
    requires static com.sun.jna;
    requires static com.sun.jna.platform;
}
