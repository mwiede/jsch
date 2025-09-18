package com.jcraft.jsch;

import java.util.Collection;
import java.util.Map;

/**
 * Represents an OpenSSH certificate containing all the fields defined in the OpenSSH certificate
 * format.
 *
 * <p>
 * OpenSSH certificates are a mechanism for providing cryptographic proof of authorization to access
 * SSH resources. They consist of a public key along with identity information and usage
 * restrictions that have been signed by a certificate authority (CA).
 * </p>
 *
 * <p>
 * This class supports both user certificates (for authenticating users to hosts) and host
 * certificates (for authenticating hosts to users).
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/draft-miller-ssh-cert-03">OpenSSH Certificate
 *      Protocol</a>
 */
class OpenSshCertificate {

  /**
   * Certificate type constant for user certificates
   */
  public static final int SSH2_CERT_TYPE_USER = 1;

  /**
   * Certificate type constant for user certificates
   */
  public static final int SSH2_CERT_TYPE_HOST = 2;

  /**
   * Minimum validity period (epoch start)
   */
  public static final long MIN_VALIDITY = 0L;

  /**
   * Maximum validity period (maximum unsigned 64-bit value)
   */
  public static final long MAX_VALIDITY = 0xffff_ffff_ffff_ffffL;

  /**
   * The certificate key type (e.g., "ssh-rsa-cert-v01@openssh.com")
   */
  private final String keyType;

  /**
   * Random nonce to make certificates unique
   */
  private final byte[] nonce;

  /**
   * The certificate's public key in SSH wire format
   */
  private final byte[] certificatePublicKey;

  /**
   * Certificate serial number
   */
  private final long serial;

  /**
   * Certificate type (user or host)
   */
  private final int type;

  /**
   * Certificate identifier string
   */
  private final String id;

  /**
   * Collection of principal names this certificate is valid for
   */
  private final Collection<String> principals;

  // match ssh-keygen behavior where the default is the epoch
  private final long validAfter;

  // match ssh-keygen behavior where the default would be forever
  private final long validBefore;

  /**
   * Critical options that must be recognized by the SSH implementation
   */
  private final Map<String, String> criticalOptions;

  /**
   * Extensions that provide additional functionality
   */
  private final Map<String, String> extensions;

  /**
   * Reserved field for future use
   */
  private final String reserved;

  /**
   * The CA's public key that signed this certificate
   */
  private final byte[] signatureKey;

  /**
   * The cryptographic signature of the certificate
   */
  private final byte[] signature;

  /**
   * Private constructor to be used exclusively by the Builder.
   */
  private OpenSshCertificate(Builder builder) {
    this.keyType = builder.keyType;
    this.nonce = builder.nonce;
    this.certificatePublicKey = builder.certificatePublicKey;
    this.serial = builder.serial;
    this.type = builder.type;
    this.id = builder.id;
    this.principals = builder.principals;
    this.validAfter = builder.validAfter;
    this.validBefore = builder.validBefore;
    this.criticalOptions = builder.criticalOptions;
    this.extensions = builder.extensions;
    this.reserved = builder.reserved;
    this.signatureKey = builder.signatureKey;
    this.signature = builder.signature;
  }

  public String getKeyType() {
    return keyType;
  }

  public byte[] getNonce() {
    return nonce;
  }

  public byte[] getCertificatePublicKey() {
    return certificatePublicKey;
  }

  public long getSerial() {
    return serial;
  }

  public int getType() {
    return type;
  }

  public String getId() {
    return id;
  }

  public Collection<String> getPrincipals() {
    return principals;
  }

  public long getValidAfter() {
    return validAfter;
  }

  public long getValidBefore() {
    return validBefore;
  }

  public Map<String, String> getCriticalOptions() {
    return criticalOptions;
  }

  public Map<String, String> getExtensions() {
    return extensions;
  }

  public String getReserved() {
    return reserved;
  }

  public byte[] getSignatureKey() {
    return signatureKey;
  }

  public byte[] getSignature() {
    return signature;
  }

  public boolean isUserCertificate() {
    return SSH2_CERT_TYPE_USER == type;
  }

  public boolean isHostCertificate() {
    return SSH2_CERT_TYPE_HOST == type;
  }

  public boolean isValidNow() {
    return OpenSshCertificateUtil.isValidNow(this);
  }

  /**
   * A static inner builder class for creating immutable OpenSshCertificate instances.
   */
  public static class Builder {
    private String keyType;
    private byte[] nonce;
    private byte[] certificatePublicKey;
    private long serial;
    private int type;
    private String id;
    private Collection<String> principals;
    private long validAfter = MIN_VALIDITY;
    private long validBefore = MAX_VALIDITY;
    private Map<String, String> criticalOptions;
    private Map<String, String> extensions;
    private String reserved;
    private byte[] signatureKey;
    private byte[] signature;

    public Builder() {}

    public Builder keyType(String keyType) {
      this.keyType = keyType;
      return this;
    }

    public Builder nonce(byte[] nonce) {
      this.nonce = nonce;
      return this;
    }

    public Builder certificatePublicKey(byte[] pk) {
      this.certificatePublicKey = pk;
      return this;
    }

    public Builder serial(long serial) {
      this.serial = serial;
      return this;
    }

    public Builder type(int type) {
      this.type = type;
      return this;
    }

    public Builder id(String id) {
      this.id = id;
      return this;
    }

    public Builder principals(Collection<String> principals) {
      this.principals = principals;
      return this;
    }

    public Builder validAfter(long validAfter) {
      this.validAfter = validAfter;
      return this;
    }

    public Builder validBefore(long validBefore) {
      this.validBefore = validBefore;
      return this;
    }

    public Builder criticalOptions(Map<String, String> opts) {
      this.criticalOptions = opts;
      return this;
    }

    public Builder extensions(Map<String, String> exts) {
      this.extensions = exts;
      return this;
    }

    public Builder reserved(String reserved) {
      this.reserved = reserved;
      return this;
    }

    public Builder signatureKey(byte[] sigKey) {
      this.signatureKey = sigKey;
      return this;
    }

    public Builder signature(byte[] signature) {
      this.signature = signature;
      return this;
    }

    /**
     * Constructs and returns an immutable OpenSshCertificate instance.
     *
     * @return A new, immutable OpenSshCertificate object.
     */
    public OpenSshCertificate build() {
      // You could add validation logic here if needed (e.g., check for null required fields)
      return new OpenSshCertificate(this);
    }
  }
}
