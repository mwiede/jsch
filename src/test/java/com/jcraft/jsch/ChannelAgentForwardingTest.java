package com.jcraft.jsch;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.Arrays;
import java.util.Vector;
import org.junit.jupiter.api.Test;

/**
 * Tests that the agent forwarding channel reports the outcome the {@link IdentityRepository}
 * actually produced, rather than always claiming success.
 */
class ChannelAgentForwardingTest {

  // Mirrors the constants of ChannelAgentForwarding, which are private there.
  private static final byte SSH_AGENT_FAILURE = 5;
  private static final byte SSH_AGENT_SUCCESS = 6;
  private static final byte SSH2_AGENTC_REMOVE_IDENTITY = 18;
  private static final byte SSH2_AGENTC_REMOVE_ALL_IDENTITIES = 19;

  private static final byte[] BLOB = Util.str2byte("not really a public key blob");

  @Test
  void removeIdentityReportsFailureWhenRepositoryRefuses() throws Exception {
    StubIdentityRepository repo = new StubIdentityRepository();
    repo.removeResult = false;

    assertEquals(SSH_AGENT_FAILURE, exchange(repo, removeIdentityRequest()));
    assertEquals(1, repo.removeCalls);
  }

  @Test
  void removeIdentityReportsSuccessWhenRepositoryRemoves() throws Exception {
    StubIdentityRepository repo = new StubIdentityRepository();
    repo.removeResult = true;

    assertEquals(SSH_AGENT_SUCCESS, exchange(repo, removeIdentityRequest()));
    assertEquals(1, repo.removeCalls);
  }

  @Test
  void removeAllIdentitiesReportsFailureWhenRepositoryRefuses() throws Exception {
    StubIdentityRepository repo = new StubIdentityRepository();
    repo.removeAllResult = false;

    assertEquals(SSH_AGENT_FAILURE, exchange(repo, removeAllIdentitiesRequest()));
    assertEquals(1, repo.removeAllCalls);
  }

  @Test
  void removeAllIdentitiesReportsSuccessWhenRepositoryRemovesThem() throws Exception {
    StubIdentityRepository repo = new StubIdentityRepository();
    repo.removeAllResult = true;

    assertEquals(SSH_AGENT_SUCCESS, exchange(repo, removeAllIdentitiesRequest()));
    assertEquals(1, repo.removeAllCalls);
  }

  /**
   * A repository that only implements the {@code void} {@link IdentityRepository#removeAll()} keeps
   * the pre-existing behaviour of always reporting success.
   */
  @Test
  void removeAllIdentitiesReportsSuccessForARepositoryWithoutAnOutcome() throws Exception {
    LegacyIdentityRepository repo = new LegacyIdentityRepository();

    assertEquals(SSH_AGENT_SUCCESS, exchange(repo, removeAllIdentitiesRequest()));
    assertEquals(1, repo.removeAllCalls);
  }

  /** Existing AgentIdentityRepository subclasses must retain their remove-all policy hooks. */
  @Test
  void removeAllIdentitiesUsesLegacyAgentRepositorySubclassOverride() throws Exception {
    StubAgentConnector connector = new StubAgentConnector(SSH_AGENT_SUCCESS);
    LegacyAgentIdentityRepository repo = new LegacyAgentIdentityRepository(connector);

    assertEquals(SSH_AGENT_SUCCESS, exchange(repo, removeAllIdentitiesRequest()));
    assertEquals(1, repo.removeAllCalls);
    assertEquals(0, connector.queries, "the overridden policy must prevent querying the agent");
  }

  /** A locked or otherwise unwilling agent answers with a failure, and so must the channel. */
  @Test
  void removeAllIdentitiesReportsFailureWhenTheAgentRefuses() throws Exception {
    StubAgentConnector connector = new StubAgentConnector(SSH_AGENT_FAILURE);

    assertEquals(SSH_AGENT_FAILURE,
        exchange(new AgentIdentityRepository(connector), removeAllIdentitiesRequest()));
    assertEquals(1, connector.queries, "the agent should be asked exactly once");
  }

  /** An unreachable agent removed nothing, so the removal must not be reported as successful. */
  @Test
  void removeAllIdentitiesReportsFailureWhenTheAgentIsUnreachable() throws Exception {
    StubAgentConnector connector = new StubAgentConnector(null);

    assertEquals(SSH_AGENT_FAILURE,
        exchange(new AgentIdentityRepository(connector), removeAllIdentitiesRequest()));
    assertEquals(1, connector.queries, "the agent should be asked exactly once");
  }

  @Test
  void removeAllIdentitiesReportsSuccessWhenTheAgentAcknowledges() throws Exception {
    StubAgentConnector connector = new StubAgentConnector(SSH_AGENT_SUCCESS);

    assertEquals(SSH_AGENT_SUCCESS,
        exchange(new AgentIdentityRepository(connector), removeAllIdentitiesRequest()));
    assertEquals(1, connector.queries, "the agent should be asked exactly once");
  }

  /** byte[]: uint32 length, byte type, string blob. */
  private static byte[] removeIdentityRequest() {
    Buffer buf = new Buffer(4 + 1 + 4 + BLOB.length);
    buf.putInt(1 + 4 + BLOB.length);
    buf.putByte(SSH2_AGENTC_REMOVE_IDENTITY);
    buf.putString(BLOB);
    return buf.buffer;
  }

  /** byte[]: uint32 length, byte type. */
  private static byte[] removeAllIdentitiesRequest() {
    Buffer buf = new Buffer(4 + 1);
    buf.putInt(1);
    buf.putByte(SSH2_AGENTC_REMOVE_ALL_IDENTITIES);
    return buf.buffer;
  }

  /** Feeds one agent request to the channel and returns the type byte of the reply. */
  private static byte exchange(IdentityRepository repo, byte[] request) throws Exception {
    RecordingSession session = new RecordingSession();
    session.setIdentityRepository(repo);

    ChannelAgentForwarding channel = new ChannelAgentForwarding();
    channel.setSession(session);
    channel.setRecipient(0);
    channel.setRemotePacketSize(0x4000);

    channel.write(request, 0, request.length);

    assertNotNull(session.channelData, "no reply was written to the channel");
    return agentReplyType(session.channelData);
  }

  /**
   * Unwraps SSH_MSG_CHANNEL_DATA (byte type, uint32 recipient, string data) whose data is one
   * length prefixed agent message, and returns that message's type byte.
   */
  private static byte agentReplyType(byte[] channelData) {
    Buffer buf = new Buffer(channelData);
    buf.index = channelData.length;
    assertEquals(Session.SSH_MSG_CHANNEL_DATA, buf.getByte(), "not a channel data message");
    buf.getInt(); // recipient
    byte[] message = buf.getString(); // the length prefixed agent message
    assertEquals(message.length - 4, new Buffer(message).getInt(), "bad agent message length");
    return message[4];
  }

  /** A session that captures what a channel writes instead of putting it on a socket. */
  private static final class RecordingSession extends Session {
    byte[] channelData;

    RecordingSession() throws JSchException {
      super(new JSch(), null, null, 0);
    }

    @Override
    void write(Packet packet, Channel c, int length) {
      // Packet#reset() leaves five bytes of room for the packet length and padding.
      channelData = Arrays.copyOfRange(packet.buffer.buffer, 5, packet.buffer.index);
    }
  }

  /** Answers every query with one reply byte, or fails outright when that byte is null. */
  private static final class StubAgentConnector implements AgentConnector {
    private final Byte reply;
    int queries;

    StubAgentConnector(Byte reply) {
      this.reply = reply;
    }

    @Override
    public String getName() {
      return "stub";
    }

    @Override
    public boolean isAvailable() {
      return true;
    }

    @Override
    public void query(Buffer buffer) throws AgentProxyException {
      queries++;
      if (reply == null) {
        throw new AgentProxyException("the agent is unreachable");
      }
      // As the real connectors do: the reply replaces the request, without its length prefix.
      buffer.rewind();
      buffer.buffer[0] = reply.byteValue();
    }
  }

  private static final class LegacyAgentIdentityRepository extends AgentIdentityRepository {
    int removeAllCalls;

    LegacyAgentIdentityRepository(AgentConnector connector) {
      super(connector);
    }

    @Override
    public void removeAll() {
      removeAllCalls++;
    }
  }

  private static final class StubIdentityRepository implements IdentityRepository {
    final Vector<Identity> identities = new Vector<>();
    boolean removeResult;
    boolean removeAllResult = true;
    int removeCalls;
    int removeAllCalls;

    @Override
    public String getName() {
      return "stub";
    }

    @Override
    public int getStatus() {
      return RUNNING;
    }

    @Override
    public Vector<Identity> getIdentities() {
      return new Vector<>(identities);
    }

    @Override
    public boolean add(byte[] identity) {
      return false;
    }

    @Override
    public boolean remove(byte[] blob) {
      removeCalls++;
      return removeResult;
    }

    @Override
    public void removeAll() {
      identities.removeAllElements();
    }

    @Override
    public boolean removeAllIdentities() {
      removeAllCalls++;
      if (removeAllResult) {
        removeAll();
      }
      return removeAllResult;
    }
  }

  /**
   * A repository predating {@link IdentityRepository#removeAllIdentities()}, which therefore only
   * implements the {@code void} {@link IdentityRepository#removeAll()}.
   */
  private static final class LegacyIdentityRepository implements IdentityRepository {
    int removeAllCalls;

    @Override
    public String getName() {
      return "legacy";
    }

    @Override
    public int getStatus() {
      return RUNNING;
    }

    @Override
    public Vector<Identity> getIdentities() {
      return new Vector<>();
    }

    @Override
    public boolean add(byte[] identity) {
      return false;
    }

    @Override
    public boolean remove(byte[] blob) {
      return false;
    }

    @Override
    public void removeAll() {
      removeAllCalls++;
    }
  }
}
