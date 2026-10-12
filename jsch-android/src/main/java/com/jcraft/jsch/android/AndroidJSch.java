// SPDX-License-Identifier: BSD-3-Clause
package com.jcraft.jsch.android;

import com.jcraft.jsch.JSch;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;

public final class AndroidJSch {
  private AndroidJSch() {}

  public static void configure() {
    if (canSign(new SignatureEd25519(), 32)) {
      JSch.setConfig("ssh-ed25519", SignatureEd25519.class.getName());
    }
    if (canSign(new SignatureEd448(), 57)) {
      JSch.setConfig("ssh-ed448", SignatureEd448.class.getName());
    }
    if (hasServices("X25519", "KeyAgreement", "KeyPairGenerator", "KeyFactory")) {
      JSch.setConfig("xdh", AndroidXDH.class.getName());
    }
  }

  private static boolean canSign(AndroidSignatureEdDSA signature, int keyLength) {
    try {
      signature.init();
      signature.setPrvKey(new byte[keyLength]);
      signature.update(new byte[0]);
      signature.sign();
      return true;
    } catch (Exception | LinkageError e) {
      return false;
    }
  }

  static Provider provider(String algorithm, String... services) throws NoSuchAlgorithmException {
    for (Provider provider : Security.getProviders()) {
      boolean supported = true;
      for (String service : services) {
        if (provider.getService(service, algorithm) == null) {
          supported = false;
          break;
        }
      }
      if (supported) {
        return provider;
      }
    }
    throw new NoSuchAlgorithmException("no provider for " + algorithm);
  }

  static boolean hasServices(String algorithm, String... services) {
    try {
      provider(algorithm, services);
      return true;
    } catch (NoSuchAlgorithmException e) {
      return false;
    }
  }
}
