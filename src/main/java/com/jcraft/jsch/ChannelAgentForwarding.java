/*
 * Copyright (c) 2006-2018 ymnk, JCraft,Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted
 * provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions
 * and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of
 * conditions and the following disclaimer in the documentation and/or other materials provided with
 * the distribution.
 *
 * 3. The names of the authors may not be used to endorse or promote products derived from this
 * software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL JCRAFT, INC. OR ANY CONTRIBUTORS TO THIS SOFTWARE BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.jcraft.jsch;

import java.io.IOException;
import java.net.*;
import java.util.Vector;

class ChannelAgentForwarding extends Channel {

  static private final int LOCAL_WINDOW_SIZE_MAX = 0x20000;
  static private final int LOCAL_MAXIMUM_PACKET_SIZE = 0x4000;

  static private final byte SSH_AGENTC_REQUEST_RSA_IDENTITIES = 1;
  static private final byte SSH_AGENT_RSA_IDENTITIES_ANSWER = 2;
  static private final byte SSH_AGENTC_RSA_CHALLENGE = 3;
  static private final byte SSH_AGENT_RSA_RESPONSE = 4;
  static private final byte SSH_AGENT_FAILURE = 5;
  static private final byte SSH_AGENT_SUCCESS = 6;
  static private final byte SSH_AGENTC_ADD_RSA_IDENTITY = 7;
  static private final byte SSH_AGENTC_REMOVE_RSA_IDENTITY = 8;
  static private final byte SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES = 9;

  static private final byte SSH2_AGENTC_REQUEST_IDENTITIES = 11;
  static private final byte SSH2_AGENT_IDENTITIES_ANSWER = 12;
  static private final byte SSH2_AGENTC_SIGN_REQUEST = 13;
  static private final byte SSH2_AGENT_SIGN_RESPONSE = 14;
  static private final byte SSH2_AGENTC_ADD_IDENTITY = 17;
  static private final byte SSH2_AGENTC_REMOVE_IDENTITY = 18;
  static private final byte SSH2_AGENTC_REMOVE_ALL_IDENTITIES = 19;
  static private final byte SSH2_AGENT_FAILURE = 30;

  // static private final int SSH_AGENT_OLD_SIGNATURE=0x1;
  static private final int SSH_AGENT_RSA_SHA2_256 = 0x2;
  static private final int SSH_AGENT_RSA_SHA2_512 = 0x4;

  private Buffer rbuf = null;
  private Buffer wbuf = null;
  private Packet packet = null;
  private Buffer mbuf = null;

  ChannelAgentForwarding() {
    super();

    setLocalWindowSizeMax(LOCAL_WINDOW_SIZE_MAX);
    setLocalWindowSize(LOCAL_WINDOW_SIZE_MAX);
    setLocalPacketSize(LOCAL_MAXIMUM_PACKET_SIZE);

    type = Util.str2byte("auth-agent@openssh.com");
    rbuf = new Buffer();
    rbuf.reset();
    // wbuf=new Buffer(rmpsize);
    // packet=new Packet(wbuf);
    mbuf = new Buffer();
    connected = true;
  }

  @Override
  void run() {
    try {
      sendOpenConfirmation();
    } catch (Exception e) {
      close = true;
      disconnect();
    }
  }

  @Override
  void write(byte[] foo, int s, int l) throws IOException {

    if (packet == null) {
      wbuf = new Buffer(rmpsize);
      packet = new Packet(wbuf);
    }

    rbuf.shift();
    if (rbuf.buffer.length < rbuf.index + l) {
      byte[] newbuf = new byte[rbuf.s + l];
      System.arraycopy(rbuf.buffer, 0, newbuf, 0, rbuf.buffer.length);
      rbuf.buffer = newbuf;
    }

    rbuf.putByte(foo, s, l);

    int mlen = rbuf.getInt();
    if (mlen > rbuf.getLength()) {
      rbuf.s -= 4;
      return;
    }

    int typ = rbuf.getByte();

    Session _session = null;
    try {
      _session = getSession();
    } catch (JSchException e) {
      throw new IOException(e.toString(), e);
    }

    IdentityRepository irepo = _session.getIdentityRepository();
    UserInfo userinfo = _session.getUserInfo();

    mbuf.reset();

    if (typ == SSH2_AGENTC_REQUEST_IDENTITIES) {
      mbuf.putByte(SSH2_AGENT_IDENTITIES_ANSWER);
      Vector<Identity> identities = irepo.getIdentities();
      synchronized (identities) {
        int count = 0;
        for (int i = 0; i < identities.size(); i++) {
          Identity identity = identities.elementAt(i);
          if (identity.getPublicKeyBlob() != null)
            count++;
        }
        mbuf.putInt(count);
        for (int i = 0; i < identities.size(); i++) {
          Identity identity = identities.elementAt(i);
          byte[] pubkeyblob = identity.getPublicKeyBlob();
          if (pubkeyblob == null)
            continue;
          mbuf.putString(pubkeyblob);
          mbuf.putString(Util.empty);
        }
      }
    } else if (typ == SSH_AGENTC_REQUEST_RSA_IDENTITIES) {
      mbuf.putByte(SSH_AGENT_RSA_IDENTITIES_ANSWER);
      mbuf.putInt(0);
    } else if (typ == SSH2_AGENTC_SIGN_REQUEST) {
      byte[] blob = rbuf.getString();
      byte[] data = rbuf.getString();
      int flags = rbuf.getInt();

      // if((flags & SSH_AGENT_OLD_SIGNATURE)!=0){ // old OpenSSH 2.0, 2.1
      // datafellows = SSH_BUG_SIGBLOB;
      // }

      Vector<Identity> identities = irepo.getIdentities();
      Identity identity = null;
      synchronized (identities) {
        for (int i = 0; i < identities.size(); i++) {
          Identity _identity = identities.elementAt(i);
          if (_identity.getPublicKeyBlob() == null)
            continue;
          if (!Util.array_equals(blob, _identity.getPublicKeyBlob())) {
            continue;
          }
          if (_identity.isEncrypted()) {
            if (userinfo == null)
              continue;
            while (_identity.isEncrypted()) {
              if (!userinfo.promptPassphrase("Passphrase for " + _identity.getName())) {
                break;
              }

              String _passphrase = userinfo.getPassphrase();
              if (_passphrase == null) {
                break;
              }

              byte[] passphrase = Util.str2byte(_passphrase);
              try {
                if (_identity.setPassphrase(passphrase)) {
                  break;
                }
              } catch (JSchException e) {
                break;
              }
            }
          }

          if (!_identity.isEncrypted()) {
            identity = _identity;
            break;
          }
        }
      }

      byte[] signature = null;

      if (identity != null) {
        Buffer kbuf = new Buffer(blob);
        String keytype = Util.byte2str(kbuf.getString());
        if (keytype.equals("ssh-rsa")) {
          if ((flags & SSH_AGENT_RSA_SHA2_256) != 0) {
            signature = identity.getSignature(data, "rsa-sha2-256");
          } else if ((flags & SSH_AGENT_RSA_SHA2_512) != 0) {
            signature = identity.getSignature(data, "rsa-sha2-512");
          } else {
            signature = identity.getSignature(data, "ssh-rsa");
          }
        } else {
          signature = identity.getSignature(data);
        }
      }

      if (signature == null) {
        mbuf.putByte(SSH2_AGENT_FAILURE);
      } else {
        mbuf.putByte(SSH2_AGENT_SIGN_RESPONSE);
        mbuf.putString(signature);
      }
    } else if (typ == SSH2_AGENTC_REMOVE_IDENTITY) {
      byte[] blob = rbuf.getString();
      irepo.remove(blob);
      mbuf.putByte(SSH_AGENT_SUCCESS);
    } else if (typ == SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES) {
      mbuf.putByte(SSH_AGENT_SUCCESS);
    } else if (typ == SSH2_AGENTC_REMOVE_ALL_IDENTITIES) {
      irepo.removeAll();
      mbuf.putByte(SSH_AGENT_SUCCESS);
    } else if (typ == SSH2_AGENTC_ADD_IDENTITY) {
      int fooo = rbuf.getLength();
      byte[] tmp = new byte[fooo];
      rbuf.getByte(tmp);
      boolean result = irepo.add(tmp);
      mbuf.putByte(result ? SSH_AGENT_SUCCESS : SSH_AGENT_FAILURE);
    } else {
      rbuf.skip(rbuf.getLength() - 1);
      mbuf.putByte(SSH_AGENT_FAILURE);
    }

    byte[] response = new byte[mbuf.getLength()];
    mbuf.getByte(response);
    send(response);
  }

  private void send(byte[] message) {
    packet.reset();
    wbuf.putByte((byte) Session.SSH_MSG_CHANNEL_DATA);
    wbuf.putInt(recipient);
    wbuf.putInt(4 + message.length);
    wbuf.putString(message);

    try {
      getSession().write(packet, this, 4 + message.length);
    } catch (Exception e) {
    }
  }

  @Override
  void eof_remote() {
    super.eof_remote();
    eof();
  }
}
