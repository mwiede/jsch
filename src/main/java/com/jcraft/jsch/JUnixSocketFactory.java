/*
 * Copyright (c) 2011 ymnk, JCraft,Inc. All rights reserved.
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

import com.jcraft.jsch.AgentProxyException;
import com.jcraft.jsch.USocketFactory;

import org.newsclub.net.unix.AFUNIXServerSocketChannel;
import org.newsclub.net.unix.AFUNIXSocketChannel;
import org.newsclub.net.unix.AFUNIXSocketAddress;

import java.io.IOException;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.file.Path;

public class JUnixSocketFactory implements USocketFactory {

  @SuppressWarnings("try")
  public JUnixSocketFactory() throws AgentProxyException {
    // Check to confirm that junixsocket library is available
    try (AFUNIXSocketChannel foo = AFUNIXSocketChannel.open()) {
    } catch (IOException | NoClassDefFoundError e) {
      throw new AgentProxyException("junixsocket library unavailable", e);
    }
  }

  @Override
  public SocketChannel connect(Path path) throws IOException {
    AFUNIXSocketAddress sockAddr = AFUNIXSocketAddress.of(path);
    AFUNIXSocketChannel sock = AFUNIXSocketChannel.open();
    sock.configureBlocking(true);
    sock.connect(sockAddr);
    return sock;
  }

  @Override
  public ServerSocketChannel bind(Path path) throws IOException {
    AFUNIXSocketAddress sockAddr = AFUNIXSocketAddress.of(path);
    AFUNIXServerSocketChannel sock = AFUNIXServerSocketChannel.open();
    sock.configureBlocking(true);
    sock.bind(sockAddr);
    return sock;
  }
}
