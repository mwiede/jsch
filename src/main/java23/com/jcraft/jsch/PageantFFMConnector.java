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
import com.jcraft.jsch.windowsapi.windows.win32.system.dataexchange.COPYDATASTRUCT;
import com.jcraft.jsch.windowsapi.windows.win32.system.memory.FILE_MAP;
import com.jcraft.jsch.windowsapi.windows.win32.system.memory.MEMORY_MAPPED_VIEW_ADDRESS;
import com.jcraft.jsch.windowsapi.windows.win32.system.memory.PAGE_PROTECTION_FLAGS;
import java.lang.foreign.Arena;
import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.StructLayout;
import java.lang.invoke.VarHandle;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

import static com.jcraft.jsch.windowsapi.windows.win32.foundation.Constants.INVALID_HANDLE_VALUE;
import static com.jcraft.jsch.windowsapi.windows.win32.foundation.Apis.CloseHandle;
import static com.jcraft.jsch.windowsapi.windows.win32.system.memory.Apis.CreateFileMappingA;
import static com.jcraft.jsch.windowsapi.windows.win32.system.memory.Apis.MapViewOfFile;
import static com.jcraft.jsch.windowsapi.windows.win32.system.memory.Apis.UnmapViewOfFile;
import static com.jcraft.jsch.windowsapi.windows.win32.system.threading.Apis.GetCurrentProcessId;
import static com.jcraft.jsch.windowsapi.windows.win32.system.threading.Apis.GetCurrentThreadId;
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

      String threadId = JavaVersion.getVersion() >= 19
          ? String.format(Locale.ROOT, "%08x%08x", GetCurrentProcessId(), JavaThreadId.get())
          : String.format(Locale.ROOT, "%08x", GetCurrentThreadId());
      MemorySegment mapname =
          arena.allocateFrom("JSchPageantRequest" + threadId, StandardCharsets.US_ASCII);

      try {
        // TODO
        MemorySegment psa = MemorySegment.NULL;

        sharedFile = CreateFileMappingA(errorState, INVALID_HANDLE_VALUE, psa,
            PAGE_PROTECTION_FLAGS.PAGE_READWRITE, 0, AGENT_MAX_MSGLEN, mapname);
        int lastError = (int) getLastErrorVarHandle.get(errorState, 0);
        if (sharedFile.equals(MemorySegment.NULL)) {
          throw new AgentProxyException(
              "Unable to create shared file mapping: GetLastError() = " + lastError);
        }
        if (lastError == WIN32_ERROR.ERROR_ALREADY_EXISTS) {
          throw new AgentProxyException("Shared file mapping already exists");
        }

        mmva = MapViewOfFile(arena, errorState, sharedFile, FILE_MAP.WRITE, 0, 0, 0);
        sharedMemory = MEMORY_MAPPED_VIEW_ADDRESS.Value(mmva);
        if (sharedMemory.equals(MemorySegment.NULL)) {
          throw new AgentProxyException("Unable to create shared memory mapping: GetLastError() = "
              + (int) getLastErrorVarHandle.get(errorState, 0));
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
        if (!sharedMemory.equals(MemorySegment.NULL))
          UnmapViewOfFile(errorState, mmva);
        if (!sharedFile.equals(MemorySegment.NULL))
          CloseHandle(errorState, sharedFile);
      }
    }
  }
}
