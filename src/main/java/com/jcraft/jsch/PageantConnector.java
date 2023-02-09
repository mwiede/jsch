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

import com.sun.jna.Platform;
import com.sun.jna.Native;
import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;

import com.sun.jna.win32.W32APIOptions;

import com.sun.jna.platform.win32.WinNT.HANDLE;
import com.sun.jna.platform.win32.WinDef.HWND;
import com.sun.jna.platform.win32.WinBase;
import com.sun.jna.platform.win32.WinBase.SECURITY_ATTRIBUTES;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.WinNT;
import com.sun.jna.platform.win32.WinUser;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

public class PageantConnector implements AgentConnector {

  private static final int AGENT_MAX_MSGLEN = 262144;
  private static final int AGENT_COPYDATA_ID = 0x804e50ba;

  private User32 libU = null;
  private Kernel32 libK = null;

  public PageantConnector() throws AgentProxyException {
    if (!Util.getSystemProperty("os.name", "").startsWith("Windows")) {
      throw new AgentProxyException("PageantConnector only available on Windows.");
    }

    try {
      libU = User32.INSTANCE;
      libK = Kernel32.INSTANCE;
    } catch (UnsatisfiedLinkError | NoClassDefFoundError e) {
      throw new AgentProxyException(e.toString(), e);
    }
  }

  @Override
  public String getName() {
    return "pageant";
  }

  @Override
  public boolean isAvailable() {
    return libU.FindWindow("Pageant", "Pageant") != null;
  }

  private interface User32 extends com.sun.jna.platform.win32.User32 {
    User32 INSTANCE = Native.load("user32", User32.class, W32APIOptions.DEFAULT_OPTIONS);

    long SendMessage(HWND hWnd, int msg, WPARAM num1, byte[] num2);
  }

  public static class COPYDATASTRUCT32 extends Structure {
    public int dwData;
    public int cbData;
    public Pointer lpData;

    @Override
    protected List<String> getFieldOrder() {
      return Arrays.asList(new String[] {"dwData", "cbData", "lpData"});
    }
  }

  public static class COPYDATASTRUCT64 extends Structure {
    public int dwData;
    public long cbData;
    public Pointer lpData;

    @Override
    protected List<String> getFieldOrder() {
      return Arrays.asList(new String[] {"dwData", "cbData", "lpData"});
    }
  }

  @Override
  public void query(Buffer buffer) throws AgentProxyException {
    if (buffer.getLength() > AGENT_MAX_MSGLEN) {
      throw new AgentProxyException("Query too large.");
    }

    HWND hwnd = libU.FindWindow("Pageant", "Pageant");

    if (hwnd == null) {
      throw new AgentProxyException("Pageant is not runnning.");
    }

    String mapname = String.format("PageantRequest%08x", libK.GetCurrentThreadId());

    // TODO
    SECURITY_ATTRIBUTES psa = null;

    HANDLE sharedFile = libK.CreateFileMapping(WinBase.INVALID_HANDLE_VALUE, psa,
        WinNT.PAGE_READWRITE, 0, AGENT_MAX_MSGLEN, mapname);
    if (sharedFile == null || sharedFile == WinBase.INVALID_HANDLE_VALUE) {
      throw new AgentProxyException("Unable to create shared file mapping.");
    }

    Pointer sharedMemory =
        Kernel32.INSTANCE.MapViewOfFile(sharedFile, WinNT.SECTION_MAP_WRITE, 0, 0, 0);

    byte[] data = null;
    long rcode = 0;
    try {
      sharedMemory.write(0, buffer.buffer, 0, buffer.getLength());

      if (Platform.is64Bit()) {
        COPYDATASTRUCT64 cds64 = new COPYDATASTRUCT64();
        data = install64(mapname, cds64);
        rcode = sendMessage(hwnd, data);
      } else {
        COPYDATASTRUCT32 cds32 = new COPYDATASTRUCT32();
        data = install32(mapname, cds32);
        rcode = sendMessage(hwnd, data);
      }

      buffer.rewind();
      if (rcode != 0) {
        sharedMemory.read(0, buffer.buffer, 0, 4); // length
        int i = buffer.getInt();
        if (i <= 0 || i > AGENT_MAX_MSGLEN - 4) {
          throw new AgentProxyException("Illegal length: " + i);
        }
        buffer.rewind();
        buffer.checkFreeSize(i);
        sharedMemory.read(4, buffer.buffer, 0, i);
      } else {
        throw new AgentProxyException("User32.SendMessage() returned 0");
      }
    } finally {
      if (sharedMemory != null)
        libK.UnmapViewOfFile(sharedMemory);
      if (sharedFile != null)
        libK.CloseHandle(sharedFile);
    }
  }

  private static byte[] install32(String mapname, COPYDATASTRUCT32 cds) {
    cds.dwData = AGENT_COPYDATA_ID;
    cds.cbData = mapname.length() + 1;
    cds.lpData = new Memory(mapname.length() + 1);
    {
      byte[] foo = Util.str2byte(mapname, StandardCharsets.US_ASCII);
      cds.lpData.write(0, foo, 0, foo.length);
      cds.lpData.setByte(foo.length, (byte) 0);
      cds.write();
    }
    byte[] data = new byte[12];
    Pointer cdsp = cds.getPointer();
    cdsp.read(0, data, 0, 12);
    return data;
  }

  private static byte[] install64(String mapname, COPYDATASTRUCT64 cds) {
    cds.dwData = AGENT_COPYDATA_ID;
    cds.cbData = mapname.length() + 1;
    cds.lpData = new Memory(mapname.length() + 1);
    {
      byte[] foo = Util.str2byte(mapname, StandardCharsets.US_ASCII);
      cds.lpData.write(0, foo, 0, foo.length);
      cds.lpData.setByte(foo.length, (byte) 0);
      cds.write();
    }
    byte[] data = new byte[24];
    Pointer cdsp = cds.getPointer();
    cdsp.read(0, data, 0, 24);
    return data;
  }

  long sendMessage(HWND hwnd, byte[] data) {

    return libU.SendMessage(hwnd, WinUser.WM_COPYDATA, null, data);
  }
}
