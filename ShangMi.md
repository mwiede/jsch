# ShangMi (SM) Algorithm Support

## Background

The ShangMi algorithms — SM2 (asymmetric), SM3 (hash), and SM4 (symmetric) — are Chinese national
cryptographic standards published by the State Cryptography Administration (SCA) under the GB/T series:

- **SM2**: GB/T 32918 — elliptic curve cryptography over the 256-bit prime field `sm2p256v1`
- **SM3**: GB/T 32905 — 256-bit hash function (structural similarity to SHA-256)
- **SM4**: GB/T 32907 — 128-bit block cipher (successor of SMS4)

Their use in SSH is defined by the Chinese standard **GM/T 0054-2018** ("SSH protocol based on
cryptographic algorithms"). As of 2025 there is **no IETF RFC** covering SM algorithms in SSH —
no draft has been adopted by the SSH working group. The algorithm identifiers therefore follow the
GM/T convention rather than the `ssh-*` naming used by IETF-standardised algorithms.

## Status in OpenSSH

Mainline OpenSSH does **not** support SM algorithms. Support exists in a fork maintained by
[openEuler](https://gitee.com/src-openeuler/openssh), a Linux distribution developed by Huawei.
The patch set adds the following identifiers to the SSH protocol:

| Layer         | Identifier          | Description                                               |
|---------------|---------------------|-----------------------------------------------------------|
| Key exchange  | `sm2-sm3`           | SM2 KAP (GM/T 0003.3) on sm2p256v1 with SM3 exchange hash |
| Host key      | `sm2`               | SM2 public key and signature                              |
| Cipher        | `sm4-ctr`           | SM4 in CTR mode                                           |
| Cipher        | `sm4-cbc`           | SM4 in CBC mode (not exposed by openEuler sshd by default) |
| MAC           | `hmac-sm3`          | HMAC with SM3                                             |

Note that the key type string is `sm2`, not `ssh-sm2` — deviating from the IETF convention.

## Public Key Format

SM2 public key blob (SSH wire format):

```
string  "sm2"          key type
string  "sm2"          curve name
string  <ecPoint>      uncompressed EC point: 0x04 || x || y  (65 bytes)
```

SM2 signature blob:

```
string  "sm2"          algorithm identifier
string  <sig>          raw DER-encoded signature (r, s as ASN.1 SEQUENCE of INTEGERs)
```

The SM2 default signer ID is `"1234567812345678"` (16 bytes, ASCII) as specified by GM/T 0054-2018.

## Key Exchange: sm2-sm3

The `sm2-sm3` KEX reuses the `SSH_MSG_KEX_ECDH_INIT` / `SSH_MSG_KEX_ECDH_REPLY` message flow
(RFC 5656) but replaces the ECDH shared-secret computation with **SM2 Key Agreement Protocol**
(SM2 KAP, GM/T 0003.3). There is no IETF specification for this combination; the behaviour
follows the openEuler OpenSSH fork.

### SM2 KAP specifics

OpenEuler's implementation uses a *degenerate* SM2 KAP configuration in which the static key
and the ephemeral key of each party are identical (the same key pair is passed for both roles to
`SM2KAP_compute_key()`). The shared secret is a 32-byte value derived as follows:

```
w      = 127                             # (256+1)/2 - 1 for the 256-bit curve
Xs_bar = 2^w + (x(Q_self) mod 2^w)      # x-bar of client's ephemeral point
Xp_bar = 2^w + (x(Q_peer) mod 2^w)      # x-bar of server's ephemeral point
t      = d · (1 + Xs_bar)  mod n        # scalar (cofactor h = 1)
U      = t · (Xp_bar · Q_peer + Q_peer) # shared EC point
K      = SM3(xU ‖ yU ‖ ZA ‖ ZB ‖ 0x00000001)[0:32]
```

where `ZA` / `ZB` are the SM2 user digest values (GM/T 0003.1 §5.5):

```
Z = SM3(entlen ‖ ID ‖ a ‖ b ‖ Gx ‖ Gy ‖ xA ‖ yA)
```

The KAP identity value is `{0x01, 0x02, …, 0x08, 0x01, …, 0x08}` (16 raw bytes), **not** the
ASCII string `"1234567812345678"` used for host-key signatures.

> **Note:** BouncyCastle's `SM2KeyExchange` class implements the full GM/T 0003.3 standard but
> produces a different result from OpenEuler's degenerate implementation. JSch therefore uses a
> manual KAP implementation (`ECDHSM2`) that matches the C reference code exactly.

## Using ShangMi Algorithms in JSch

SM algorithm support requires **BouncyCastle** (`bcprov-jdk18on`) on the classpath. JSch checks
availability at startup via `CheckCiphers`, `CheckMacs`, and `CheckSignatures` and silently removes
unavailable algorithms from all proposals. No configuration change is needed when BC is absent.

### Connecting to an SM-only SSH server

```java
JSch jsch = new JSch();

// Load SM2 identity (SEC1 PEM private key + matching public key)
jsch.addIdentity("/path/to/id_sm2", "/path/to/id_sm2.pub", null);

// Trust the server host key
HostKey hostKey = new HostKey("[host]:port", Base64.getDecoder().decode("<base64-blob>"));
jsch.getHostKeyRepository().add(hostKey, null);

Session session = jsch.getSession("user", "host", 22);
session.setConfig("StrictHostKeyChecking", "yes");
session.setConfig("server_host_key",        "sm2");
session.setConfig("PreferredAuthentications","publickey");
session.connect();
```

If the server also mandates SM4 ciphers or HMAC-SM3, restrict the proposals explicitly:

```java
session.setConfig("cipher.s2c", "sm4-ctr");
session.setConfig("cipher.c2s", "sm4-ctr");
session.setConfig("mac.s2c",    "hmac-sm3");
session.setConfig("mac.c2s",    "hmac-sm3");
```

### Generating SM2 keys

JSch does not generate SM2 key pairs. Use OpenSSL with BouncyCastle or the openEuler `ssh-keygen`
to create keys and export them in SEC1 PEM format (`BEGIN EC PRIVATE KEY`):

```sh
# on an openEuler system:
ssh-keygen -t sm2 -f id_sm2
```

### Algorithm identifiers reference

| JSch config key            | Default value                      |
|----------------------------|------------------------------------|
| `sm2-sm3`                  | `com.jcraft.jsch.DHSM2SM3`         |
| `ecdh-sm2p256v1`           | `com.jcraft.jsch.bc.ECDHSM2`       |
| `sm2`                      | `com.jcraft.jsch.bc.SignatureSM2`  |
| `sm3`                      | `com.jcraft.jsch.bc.SM3`           |
| `hmac-sm3`                 | `com.jcraft.jsch.bc.HMACSM3`       |
| `sm4-cbc`                  | `com.jcraft.jsch.bc.SM4CBC`        |
| `sm4-ctr`                  | `com.jcraft.jsch.bc.SM4CTR`        |
