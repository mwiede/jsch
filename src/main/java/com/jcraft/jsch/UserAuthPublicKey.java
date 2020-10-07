/* -*-mode:java; c-basic-offset:2; indent-tabs-mode:nil -*- */
/*
Copyright (c) 2002-2018 ymnk, JCraft,Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

  1. Redistributions of source code must retain the above copyright notice,
     this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright 
     notice, this list of conditions and the following disclaimer in 
     the documentation and/or other materials provided with the distribution.

  3. The names of the authors may not be used to endorse or promote products
     derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL JCRAFT,
INC. OR ANY CONTRIBUTORS TO THIS SOFTWARE BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

package com.jcraft.jsch;

import java.util.Vector;

class UserAuthPublicKey extends UserAuth{

  public boolean start(Session session) throws Exception{
    super.start(session);

    Vector identities=session.getIdentityRepository().getIdentities();

    byte[] passphrase=null;
    byte[] _username=null;

    int command;

    synchronized(identities){
      if(identities.size()<=0){
        return false;
      }

      String pkmethods=session.getConfig("PubkeyAcceptedKeyTypes");
      String[] pkmethoda=Util.split(pkmethods, ",");
      if(pkmethoda.length==0){
        return false;
      }

      String rsamethods=null;
      String nonrsamethods=null;
      for(int i=0; i<pkmethoda.length; i++){
        if(pkmethoda[i].equals("ssh-rsa") || pkmethoda[i].equals("rsa-sha2-256") || pkmethoda[i].equals("rsa-sha2-512")){
          if(rsamethods==null) rsamethods=pkmethoda[i];
          else rsamethods+=","+pkmethoda[i];
        }
        else{
          if(nonrsamethods==null) nonrsamethods=pkmethoda[i];
          else nonrsamethods+=","+pkmethoda[i];
        }
      }
      String[] rsamethoda=Util.split(rsamethods, ",");
      String[] nonrsamethoda=Util.split(nonrsamethods, ",");

      _username=Util.str2byte(username);

      iloop:
      for(int i=0; i<identities.size(); i++){

        if(session.auth_failures >= session.max_auth_tries){
          return false;
        }

        Identity identity=(Identity)(identities.elementAt(i));

        String ipkmethod=identity.getAlgName();
        String[] ipkmethoda=null;
        if(ipkmethod.equals("ssh-rsa")){
          ipkmethoda=rsamethoda;
        }
        else if(nonrsamethoda!=null && nonrsamethoda.length>0){
          for(int j=0; j<nonrsamethoda.length; j++){
            if(ipkmethod.equals(nonrsamethoda[j])){
              ipkmethoda=new String[]{ipkmethod};
              break;
            }
          }
        }
        if(ipkmethoda==null) {
          if(JSch.getLogger().isEnabled(Logger.DEBUG)){
            JSch.getLogger().log(Logger.DEBUG,
                    ipkmethod+" cannot be used as public key type for identity "+identity.getName());
          }
          continue;
        }

        byte[] pubkeyblob=identity.getPublicKeyBlob();
        String[] pkmethodsuccess=null;

        if(pubkeyblob!=null){
          command=SSH_MSG_USERAUTH_FAILURE;
          loop3:
          for(int j=0; j<ipkmethoda.length; j++){
            // send
            // byte      SSH_MSG_USERAUTH_REQUEST(50)
            // string    user name
            // string    service name ("ssh-connection")
            // string    "publickey"
            // boolen    FALSE
            // string    public key algorithm name
            // string    public key blob
            packet.reset();
            buf.putByte((byte)SSH_MSG_USERAUTH_REQUEST);
            buf.putString(_username);
            buf.putString(Util.str2byte("ssh-connection"));
            buf.putString(Util.str2byte("publickey"));
            buf.putByte((byte)0);
            buf.putString(Util.str2byte(ipkmethoda[j]));
            buf.putString(pubkeyblob);
            session.write(packet);

            loop1:
            while(true){
              buf=session.read(buf);
              command=buf.getCommand()&0xff;

              if(command==SSH_MSG_USERAUTH_PK_OK){
                if(JSch.getLogger().isEnabled(Logger.DEBUG)){
                  JSch.getLogger().log(Logger.DEBUG,
                                       ipkmethoda[j] + " preauth success");
                }
                pkmethodsuccess=new String[]{ipkmethoda[j]};
                break loop3;
              }
              else if(command==SSH_MSG_USERAUTH_FAILURE){
                if(JSch.getLogger().isEnabled(Logger.DEBUG)){
                  JSch.getLogger().log(Logger.DEBUG,
                                       ipkmethoda[j] + " preauth failure");
                }
                continue loop3;
              }
              else if(command==SSH_MSG_USERAUTH_BANNER){
                buf.getInt(); buf.getByte(); buf.getByte();
                byte[] _message=buf.getString();
                byte[] lang=buf.getString();
                String message=Util.byte2str(_message);
                if(userinfo!=null){
                  userinfo.showMessage(message);
                }
                continue loop1;
              }
              else{
              //System.err.println("USERAUTH fail ("+command+")");
              //throw new JSchException("USERAUTH fail ("+command+")");
                if(JSch.getLogger().isEnabled(Logger.DEBUG)){
                  JSch.getLogger().log(Logger.DEBUG,
                                       ipkmethoda[j] + " preauth failure command (" + command + ")");
                }
                continue loop3;
              }
            }
          }

          if(command!=SSH_MSG_USERAUTH_PK_OK){
            continue iloop;
          }
        }

//System.err.println("UserAuthPublicKey: identity.isEncrypted()="+identity.isEncrypted());

        int count=5;
        while(true){
          if((identity.isEncrypted() && passphrase==null)){
            if(userinfo==null) throw new JSchException("USERAUTH fail");
            if(identity.isEncrypted() &&
               !userinfo.promptPassphrase("Passphrase for "+identity.getName())){
              throw new JSchAuthCancelException("publickey");
              //throw new JSchException("USERAUTH cancel");
              //break;
            }
            String _passphrase=userinfo.getPassphrase();
            if(_passphrase!=null){
              passphrase=Util.str2byte(_passphrase);
            }
          }

          if(!identity.isEncrypted() || passphrase!=null){
            if(identity.setPassphrase(passphrase)){
              if(passphrase!=null &&
                 (session.getIdentityRepository() instanceof IdentityRepository.Wrapper)){
                ((IdentityRepository.Wrapper)session.getIdentityRepository()).check();
              }
              break;
            }
          }
          Util.bzero(passphrase);
          passphrase=null;
          count--;
          if(count==0)break;
        }

        Util.bzero(passphrase);
        passphrase=null;
//System.err.println("UserAuthPublicKey: identity.isEncrypted()="+identity.isEncrypted());

        if(identity.isEncrypted()) continue;
        if(pubkeyblob==null) pubkeyblob=identity.getPublicKeyBlob();

//System.err.println("UserAuthPublicKey: pubkeyblob="+pubkeyblob);

        if(pubkeyblob==null) continue;
        if(pkmethodsuccess==null) pkmethodsuccess=ipkmethoda;

        loop4:
        for(int j=0; j<pkmethodsuccess.length; j++){
          // send
          // byte      SSH_MSG_USERAUTH_REQUEST(50)
          // string    user name
          // string    service name ("ssh-connection")
          // string    "publickey"
          // boolen    TRUE
          // string    public key algorithm name
          // string    public key blob
          // string    signature
          packet.reset();
          buf.putByte((byte)SSH_MSG_USERAUTH_REQUEST);
          buf.putString(_username);
          buf.putString(Util.str2byte("ssh-connection"));
          buf.putString(Util.str2byte("publickey"));
          buf.putByte((byte)1);
          buf.putString(Util.str2byte(pkmethodsuccess[j]));
          buf.putString(pubkeyblob);

//        byte[] tmp=new byte[buf.index-5];
//        System.arraycopy(buf.buffer, 5, tmp, 0, tmp.length);
//        buf.putString(signature);

          byte[] sid=session.getSessionId();
          int sidlen=sid.length;
          byte[] tmp=new byte[4+sidlen+buf.index-5];
          tmp[0]=(byte)(sidlen>>>24);
          tmp[1]=(byte)(sidlen>>>16);
          tmp[2]=(byte)(sidlen>>>8);
          tmp[3]=(byte)(sidlen);
          System.arraycopy(sid, 0, tmp, 4, sidlen);
          System.arraycopy(buf.buffer, 5, tmp, 4+sidlen, buf.index-5);
          byte[] signature=identity.getSignature(tmp, pkmethodsuccess[j]);
          if(signature==null){  // for example, too long key length.
            if(JSch.getLogger().isEnabled(Logger.DEBUG)){
              JSch.getLogger().log(Logger.DEBUG,
                                   pkmethodsuccess[j] + " signature failure");
            }
            continue loop4;
          }
          buf.putString(signature);
          session.write(packet);

          loop2:
          while(true){
            buf=session.read(buf);
            command=buf.getCommand()&0xff;

            if(command==SSH_MSG_USERAUTH_SUCCESS){
              if(JSch.getLogger().isEnabled(Logger.DEBUG)){
                JSch.getLogger().log(Logger.DEBUG,
                                     pkmethodsuccess[j] + " auth success");
              }
              return true;
            }
            else if(command==SSH_MSG_USERAUTH_BANNER){
              buf.getInt(); buf.getByte(); buf.getByte();
              byte[] _message=buf.getString();
              byte[] lang=buf.getString();
              String message=Util.byte2str(_message);
              if(userinfo!=null){
                userinfo.showMessage(message);
              }
              continue loop2;
            }
            else if(command==SSH_MSG_USERAUTH_FAILURE){
              buf.getInt(); buf.getByte(); buf.getByte();
              byte[] foo=buf.getString();
              int partial_success=buf.getByte();
            //System.err.println(new String(foo)+
            //                   " partial_success:"+(partial_success!=0));
              if(partial_success!=0){
                throw new JSchPartialAuthException(Util.byte2str(foo));
              }
              session.auth_failures++;
              if(JSch.getLogger().isEnabled(Logger.DEBUG)){
                JSch.getLogger().log(Logger.DEBUG,
                                     pkmethodsuccess[j] + " auth failure");
              }
              break loop2;
            }
            //System.err.println("USERAUTH fail ("+command+")");
            //throw new JSchException("USERAUTH fail ("+command+")");
            if(JSch.getLogger().isEnabled(Logger.DEBUG)){
              JSch.getLogger().log(Logger.DEBUG,
                                   pkmethodsuccess[j] + " auth failure command (" + command +")");
            }
            break loop2;
          }
        }
      }
    }
    return false;
  }
}
