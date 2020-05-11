
README of example directory
====================================================================
Last modified: Wed Oct 16 13:53:12 UTC 2002

This directory contains some examples, which demonstrate how to use JSch

- Shell.java
  This program enables you to connect to sshd server and get the shell prompt.
  $ CLASSPATH=.:../build javac Shell.java 
  $ CLASSPATH=.:../build java Shell
  You will be asked username, hostname and passwd. 
  If everything works fine, you will get the shell prompt. Output will
  be ugly because of lacks of terminal-emulation, but you can issue commands.

- X11Forwarding.java
  This program will demonstrate X11 forwarding.
  $ CLASSPATH=.:../build javac X11Forwarding.java 
  $ CLASSPATH=.:../build java X11Forwarding
  You will be asked username, hostname, displayname and passwd. 
  If your X server does not run at 127.0.0.1, please enter correct
  displayname. If everything works fine, you will get the shell prompt.
  Try X applications; for example, xlogo.

- Exec.java
  This program will demonstrate remote exec.
  $ CLASSPATH=.:../build javac Exec.java 
  $ CLASSPATH=.:../build java Exec
  You will be asked username, hostname, displayname, passwd and command.
  If everything works fine, given command will be invoked 
  on the remote side and outputs will be printed out.


- ViaHTTP.java
  This program will demonstrate the ssh session via HTTP proxy.
  $ CLASSPATH=.:../build javac ViaHTTP.java 
  $ CLASSPATH=.:../build java ViaHTTP
  You will be asked username, hostname, proxy-server and passwd. 
  If everything works fine, you will get the shell prompt.

- ViaSOCKS.java
  This program will demonstrate the ssh session via SOCKS proxy.
  $ CLASSPATH=.:../build javac ViaSOCKS.java 
  $ CLASSPATH=.:../build java ViaSOCKS
  You will be asked username, hostname, proxy-server and passwd. 
  If everything works fine, you will get the shell prompt.

- PortForwardingR.java
  This program will demonstrate the port forwarding like option -R of
  ssh command; the given port on the remote host will be forwarded to
  the given host and port  on the local side.
  $ CLASSPATH=.:../build javac PortForwardingR.java
  $ CLASSPATH=.:../build java PortForwardingR
  You will be asked username, hostname, port:host:hostport and passwd. 
  If everything works fine, you will get the shell prompt.
  Try the port on remote host.

- PortForwardingL.java
  This program will demonstrate the port forwarding like option -L of
  ssh command; the given port on the local host will be forwarded to
  the given remote host and port on the remote side.
  $ CLASSPATH=.:../build javac PortForwardingL.java
  $ CLASSPATH=.:../build java PortForwardingL
  You will be asked username, hostname, port:host:hostport and passwd. 
  If everything works fine, you will get the shell prompt.
  Try the port on localhost.

- StreamForwarding.java
  This program will demonstrate the stream forwarding. The given Java
  I/O streams will be forwared to the given remote host and port on
  the remote side.  It is simmilar to the -L option of ssh command,
  but you don't have to assign and open a local tcp port.
  $ CLASSPATH=.:../build javac StreamForwarding.java
  $ CLASSPATH=.:../build java StreamForwarding
  You will be asked username, hostname, host:hostport and passwd. 
  If everything works fine, System.in and System.out streams will be
  forwared to remote port and you can send messages from command line.

- UserAuthPubKey.java
  This program will demonstrate the user authentification by public key.
  $ CLASSPATH=.:../build javac UserAuthPubKey.java
  $ CLASSPATH=.:../build java UserAuthPubKey
  You will be asked username, hostname, privatekey(id_dsa) and passphrase. 
  If everything works fine, you will get the shell prompt

- Compression.java
  This program will demonstrate the packet compression.
  $ CLASSPATH=.:../build javac Compression.java
  $ CLASSPATH=.:../build java Compression
  You will be asked username, hostname and passwd. 
  If everything works fine, you will get the shell prompt. 
  In this program, all data from sshd server to jsch will be
  compressed.

- ScpTo.java
  This program will demonstrate the file transfer from local to remote.
  $ CLASSPATH=.:../build javac ScpTo.java
  $ CLASSPATH=.:../build java ScpTo file1 user@remotehost:file2
  You will be asked passwd. 
  If everything works fine, a local file 'file1' will copied to
  'file2' on 'remotehost'.

- ScpFrom.java
  This program will demonstrate the file transfer from remote to local
  $ CLASSPATH=.:../build javac ScpFrom.java
  $ CLASSPATH=.:../build java ScpFrom user@remotehost:file1 file2
  You will be asked passwd. 
  If everything works fine, a file 'file1' on 'remotehost' will copied to
  local 'file1'.

- Sftp.java
  This program will demonstrate the sftp protocol support.
  $ CLASSPATH=.:../build javac Sftp.java
  $ CLASSPATH=.:../build java Sftp
  You will be asked username, host and passwd. 
  If everything works fine, you will get a prompt 'sftp>'. 
  'help' command will show available command.
  In current implementation, the destination path for 'get' and 'put'
  commands must be a file, not a directory.

- KnownHosts.java
  This program will demonstrate the 'known_hosts' file handling.
  $ CLASSPATH=.:../build javac KnownHosts.java
  $ CLASSPATH=.:../build java KnownHosts
  You will be asked username, hostname, a path for 'known_hosts' and passwd. 
  If everything works fine, you will get the shell prompt.
  In current implementation, jsch only reads 'known_hosts' for checking
  and does not modify it.

- UserAuthKI.java
  This program will demonstrate the keyboard-interactive authentication.
  $ CLASSPATH=.:../build javac UserAuthKI.java
  $ CLASSPATH=.:../build java UserAuthKI
  If the remote sshd supports keyboard-interactive authentication,
  you will be prompted.

- KeyGen.java
  This progam will demonstrate the DSA keypair generation. 
  $ CLASSPATH=.:../build javac KeyGen.java
  $ CLASSPATH=.:../build java KeyGen rsa output_keyfile comment
or
  $ CLASSPATH=.:../build java KeyGen dsa output_keyfile comment
  You will be asked a passphrase for output_keyfile.
  If everything works fine, you will get the DSA or RSA keypair, 
  output_keyfile and output_keyfile+".pub".
  The private key and public key are in the OpenSSH format.

- ChangePassphrase.java
  This program will demonstrate to change the passphrase for a
  private key file instead of creating a new private key.
  $ CLASSPATH=.:../build javac ChangePassphrase.java
  $ CLASSPATH=.:../build java ChangePassphrase private-key
  A passphrase will be prompted if the given private-key has been
  encrypted.  After successfully loading the content of the
  private-key, the new passphrase will be prompted and the given
  private-key will be re-encrypted with that new passphrase.

- AES.java
  This program will demonstrate how to use "aes128-cbc".

- Daemon.java
  This program will demonstrate how to provide a network service like
  inetd by using remote port-forwarding functionality.

- Logger.java
  This program will demonstrate how to enable logging mechanism and
  get logging messages.

- Subsystem.java
  This program will demonstrate how to use the Subsystem channel.

- Sudo.java
  This program will demonstrate how to exec 'sudo' on the remote.

- ScpToNoneCipher.java
  This program will demonstrate how to enable none cipher.

- JumpHosts.java
  This program will demonstrate SSH through jump hosts.

- OpenSSHConfig.java
  This program will demonstrate how OpenSSH's config is supported.
