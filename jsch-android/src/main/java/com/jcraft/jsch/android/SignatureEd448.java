// SPDX-License-Identifier: BSD-3-Clause
package com.jcraft.jsch.android;

public class SignatureEd448 extends AndroidSignatureEdDSA {
  @Override
  String getName() {
    return "ssh-ed448";
  }

  @Override
  String getAlgo() {
    return "Ed448";
  }

  @Override
  int getKeylen() {
    return 57;
  }
}
