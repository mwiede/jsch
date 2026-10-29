// SPDX-License-Identifier: BSD-3-Clause
package com.jcraft.jsch.android;

public class SignatureEd25519 extends AndroidSignatureEdDSA {
  @Override
  String getName() {
    return "ssh-ed25519";
  }

  @Override
  String getAlgo() {
    return "Ed25519";
  }

  @Override
  int getKeylen() {
    return 32;
  }
}
