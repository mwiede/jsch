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

import com.jcraft.jsch.windowsapi.windows.win32.foundation.WIN32_ERROR;
import com.jcraft.jsch.windowsapi.windows.win32.security.SECURITY_ATTRIBUTES;
import com.jcraft.jsch.windowsapi.windows.win32.security.SECURITY_DESCRIPTOR;
import com.jcraft.jsch.windowsapi.windows.win32.security.SID_AND_ATTRIBUTES;
import com.jcraft.jsch.windowsapi.windows.win32.security.TOKEN_ACCESS_MASK;
import com.jcraft.jsch.windowsapi.windows.win32.security.TOKEN_INFORMATION_CLASS;
import com.jcraft.jsch.windowsapi.windows.win32.security.TOKEN_USER;
import com.jcraft.jsch.windowsapi.windows.win32.system.dataexchange.COPYDATASTRUCT;
import com.jcraft.jsch.windowsapi.windows.win32.system.memory.FILE_MAP;
import com.jcraft.jsch.windowsapi.windows.win32.system.memory.MEMORY_MAPPED_VIEW_ADDRESS;
import com.jcraft.jsch.windowsapi.windows.win32.system.memory.PAGE_PROTECTION_FLAGS;
import java.lang.foreign.Arena;
import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.StructLayout;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.VarHandle;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

import static com.jcraft.jsch.windowsapi.windows.win32.foundation.Constants.INVALID_HANDLE_VALUE;
import static com.jcraft.jsch.windowsapi.windows.win32.foundation.Apis.CloseHandle;
import static com.jcraft.jsch.windowsapi.windows.win32.security.Apis.CopySid;
import static com.jcraft.jsch.windowsapi.windows.win32.security.Apis.GetLengthSid;
import static com.jcraft.jsch.windowsapi.windows.win32.security.Apis.GetTokenInformation;
import static com.jcraft.jsch.windowsapi.windows.win32.security.Apis.InitializeSecurityDescriptor;
import static com.jcraft.jsch.windowsapi.windows.win32.security.Apis.IsValidSid;
import static com.jcraft.jsch.windowsapi.windows.win32.security.Apis.SetSecurityDescriptorOwner;
import static com.jcraft.jsch.windowsapi.windows.win32.system.memory.Apis.CreateFileMappingA;
import static com.jcraft.jsch.windowsapi.windows.win32.system.memory.Apis.MapViewOfFile;
import static com.jcraft.jsch.windowsapi.windows.win32.system.memory.Apis.UnmapViewOfFile;
import static com.jcraft.jsch.windowsapi.windows.win32.system.systemservices.Constants.MAXIMUM_ALLOWED;
import static com.jcraft.jsch.windowsapi.windows.win32.system.systemservices.Constants.SECURITY_DESCRIPTOR_REVISION;
import static com.jcraft.jsch.windowsapi.windows.win32.system.threading.Apis.GetCurrentProcessId;
import static com.jcraft.jsch.windowsapi.windows.win32.system.threading.Apis.GetCurrentThreadId;
import static com.jcraft.jsch.windowsapi.windows.win32.system.threading.Apis.OpenProcess;
import static com.jcraft.jsch.windowsapi.windows.win32.system.threading.Apis.OpenProcessToken;
import static com.jcraft.jsch.windowsapi.windows.win32.ui.windowsandmessaging.Apis.FindWindowA;
import static com.jcraft.jsch.windowsapi.windows.win32.ui.windowsandmessaging.Apis.SendMessageA;
import static com.jcraft.jsch.windowsapi.windows.win32.ui.windowsandmessaging.Constants.WM_COPYDATA;

public class PageantFFMConnector implements AgentConnector {

  private static final int AGENT_MAX_MSGLEN = 262144;
  private static final long AGENT_COPYDATA_ID = 0x804e50baL;

  private final StructLayout errorStateLayout;
  private final VarHandle getLastErrorVarHandle;

  public PageantFFMConnector() throws AgentProxyException {
    if (!Util.getSystemProperty("os.name", "").startsWith("Windows")) {
      throw new AgentProxyException("PageantFFMConnector only available on Windows.");
    }

    try {
      errorStateLayout = Linker.Option.captureStateLayout();
      getLastErrorVarHandle =
          errorStateLayout.varHandle(MemoryLayout.PathElement.groupElement("GetLastError"));

      // Force class initialization to catch UnsatisfiedLinkError
      Object foo = com.jcraft.jsch.windowsapi.windows.win32.foundation.Apis.CloseHandle$handle();
      foo = com.jcraft.jsch.windowsapi.windows.win32.security.Apis.CopySid$handle();
      foo = com.jcraft.jsch.windowsapi.windows.win32.system.memory.Apis.CreateFileMappingA$handle();
      foo = com.jcraft.jsch.windowsapi.windows.win32.system.threading.Apis
          .GetCurrentProcessId$handle();
      foo =
          com.jcraft.jsch.windowsapi.windows.win32.ui.windowsandmessaging.Apis.FindWindowA$handle();
    } catch (IllegalArgumentException | LinkageError e) {
      throw new AgentProxyException(e.toString(), e);
    }
  }

  @Override
  public String getName() {
    return "pageant_ffm";
  }

  @Override
  public boolean isAvailable() {
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment errorState = arena.allocate(errorStateLayout);
      MemorySegment pageant = arena.allocateFrom("Pageant", StandardCharsets.US_ASCII);
      return !FindWindowA(errorState, pageant, pageant).equals(MemorySegment.NULL);
    }
  }

  @Override
  public void query(Buffer buffer) throws AgentProxyException {
    if (buffer.getLength() > AGENT_MAX_MSGLEN) {
      throw new AgentProxyException("Query too large.");
    }

    try (Arena arena = Arena.ofConfined()) {
      MemorySegment sharedFile = MemorySegment.NULL;
      MemorySegment mmva = null;
      MemorySegment sharedMemory = MemorySegment.NULL;
      MemorySegment errorState = arena.allocate(errorStateLayout);
      MemorySegment pageant = arena.allocateFrom("Pageant", StandardCharsets.US_ASCII);

      MemorySegment hwnd = FindWindowA(errorState, pageant, pageant);

      if (hwnd.equals(MemorySegment.NULL)) {
        throw new AgentProxyException("Pageant is not runnning.");
      }

      MemorySegment usersid = getUserSid(arena, errorState);
      MemorySegment psd = SECURITY_DESCRIPTOR.allocate(arena);
      if (InitializeSecurityDescriptor(errorState, psd, SECURITY_DESCRIPTOR_REVISION) == 0) {
        throw new AgentProxyException("Unable to InitializeSecurityDescriptor(): GetLastError() = "
            + GetLastError(errorState));
      }
      if (SetSecurityDescriptorOwner(errorState, psd, usersid, 0) == 0) {
        throw new AgentProxyException(
            "Unable to SetSecurityDescriptorOwner(): GetLastError() = " + GetLastError(errorState));
      }

      MemorySegment psa = SECURITY_ATTRIBUTES.allocate(arena);
      SECURITY_ATTRIBUTES.nLength(psa, (int) SECURITY_ATTRIBUTES.sizeof());
      SECURITY_ATTRIBUTES.bInheritHandle(psa, 1);
      SECURITY_ATTRIBUTES.lpSecurityDescriptor(psa, psd);

      String threadId = String.format(Locale.ROOT, "%08x%08x", GetCurrentProcessId(),
          Thread.currentThread().threadId());
      MemorySegment mapname =
          arena.allocateFrom("JSchPageantRequest" + threadId, StandardCharsets.US_ASCII);

      try {
        sharedFile = CreateFileMappingA(errorState, INVALID_HANDLE_VALUE, psa,
            PAGE_PROTECTION_FLAGS.PAGE_READWRITE, 0, AGENT_MAX_MSGLEN, mapname);
        int lastError = GetLastError(errorState);
        if (sharedFile.equals(MemorySegment.NULL)) {
          throw new AgentProxyException(
              "Unable to CreateFileMapping(): GetLastError() = " + lastError);
        }
        if (lastError == WIN32_ERROR.ERROR_ALREADY_EXISTS) {
          throw new AgentProxyException("Shared file mapping already exists");
        }

        mmva = MapViewOfFile(arena, errorState, sharedFile, FILE_MAP.WRITE, 0, 0, 0);
        sharedMemory = MEMORY_MAPPED_VIEW_ADDRESS.Value(mmva);
        if (sharedMemory.equals(MemorySegment.NULL)) {
          throw new AgentProxyException(
              "Unable to MapViewOfFile(): GetLastError() = " + GetLastError(errorState));
        }
        sharedMemory = sharedMemory.reinterpret(AGENT_MAX_MSGLEN);

        MemorySegment buf = MemorySegment.ofArray(buffer.buffer);
        MemorySegment.copy(buf, 0, sharedMemory, 0, buffer.getLength());

        MemorySegment cds = COPYDATASTRUCT.allocate(arena);
        COPYDATASTRUCT.dwData(cds, AGENT_COPYDATA_ID);
        COPYDATASTRUCT.cbData(cds, (int) mapname.byteSize());
        COPYDATASTRUCT.lpData(cds, mapname);

        long rcode = SendMessageA(errorState, hwnd, WM_COPYDATA, MemorySegment.NULL.address(),
            cds.address());
        // Dummy read to make sure COPYDATASTRUCT isn't GC'd early
        long foo = COPYDATASTRUCT.dwData(cds);

        buffer.rewind();
        if (rcode != 0) {
          MemorySegment.copy(sharedMemory, 0, buf, 0, 4); // length
          int i = buffer.getInt();
          if (i <= 0 || i > AGENT_MAX_MSGLEN - 4) {
            throw new AgentProxyException("Illegal length: " + i);
          }
          buffer.rewind();
          buffer.checkFreeSize(i);
          // checkFreeSize may have created a new array
          buf = MemorySegment.ofArray(buffer.buffer);
          MemorySegment.copy(sharedMemory, 4, buf, 0, i);
        } else {
          throw new AgentProxyException(
              "SendMessage() returned 0 with cds.dwData: " + Long.toHexString(foo));
        }
      } finally {
        try {
          if (!sharedMemory.equals(MemorySegment.NULL)) {
            UnmapViewOfFile(errorState, mmva);
          }
        } finally {
          if (!sharedFile.equals(MemorySegment.NULL)) {
            CloseHandle(errorState, sharedFile);
          }
        }
      }
    }
  }

  private MemorySegment getUserSid(Arena arena, MemorySegment errorState)
      throws AgentProxyException {
    MemorySegment proc = MemorySegment.NULL;
    MemorySegment tok = MemorySegment.NULL;

    try {
      proc = OpenProcess(errorState, MAXIMUM_ALLOWED, 0, GetCurrentProcessId());
      if (proc.equals(MemorySegment.NULL)) {
        throw new AgentProxyException(
            "Unable to OpenProcess(): GetLastError() = " + GetLastError(errorState));
      }

      MemorySegment ptok = arena.allocate(ValueLayout.ADDRESS);
      if (OpenProcessToken(errorState, proc, TOKEN_ACCESS_MASK.TOKEN_QUERY, ptok) == 0) {
        throw new AgentProxyException(
            "Unable to OpenProcessToken(): GetLastError() = " + GetLastError(errorState));
      }

      tok = ptok.get(ValueLayout.ADDRESS, 0);
      if (tok.equals(MemorySegment.NULL)) {
        throw new AgentProxyException("ProcessToken is NULL");
      }

      MemorySegment ptoklen = arena.allocate(ValueLayout.JAVA_INT);
      if (GetTokenInformation(errorState, tok, TOKEN_INFORMATION_CLASS.TokenUser,
          MemorySegment.NULL, 0, ptoklen) == 0) {
        int lastError = GetLastError(errorState);
        if (lastError != WIN32_ERROR.ERROR_INSUFFICIENT_BUFFER) {
          throw new AgentProxyException(
              "Unable to GetTokenInformation() toklen: GetLastError() = " + lastError);
        }
      }

      long toklen = ptoklen.get(ValueLayout.JAVA_INT, 0) & 0xffffffffL;
      if (toklen < TOKEN_USER.sizeof()) {
        throw new AgentProxyException(String.format(Locale.ROOT,
            "toklen (%d) < sizeof(TOKEN_USER) (%d)", toklen, TOKEN_USER.sizeof()));
      }

      MemorySegment user = arena.allocate(toklen, ValueLayout.ADDRESS.byteAlignment());
      if (GetTokenInformation(errorState, tok, TOKEN_INFORMATION_CLASS.TokenUser, user,
          (int) toklen, ptoklen) == 0) {
        throw new AgentProxyException(
            "Unable to GetTokenInformation() user: GetLastError() = " + GetLastError(errorState));
      }

      MemorySegment psid = SID_AND_ATTRIBUTES.Sid(TOKEN_USER.User(user));
      if (IsValidSid(psid) == 0) {
        throw new AgentProxyException("IsValidSid() failed");
      }

      long sidlen = GetLengthSid(psid) & 0xffffffffL;
      MemorySegment usersid = arena.allocate(sidlen, ValueLayout.ADDRESS.byteAlignment());
      if (CopySid(errorState, (int) sidlen, usersid, psid) == 0) {
        throw new AgentProxyException(
            "Unable to CopySid(): GetLastError() = " + GetLastError(errorState));
      }

      return usersid;
    } finally {
      try {
        if (!tok.equals(MemorySegment.NULL)) {
          CloseHandle(errorState, tok);
        }
      } finally {
        if (!proc.equals(MemorySegment.NULL)) {
          CloseHandle(errorState, proc);
        }
      }
    }
  }

  private int GetLastError(MemorySegment errorState) {
    return (int) getLastErrorVarHandle.get(errorState, 0);
  }
}
