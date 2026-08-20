package com.jcraft.jsch;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Vector;
import org.junit.jupiter.api.Test;

/** Tests that the cached identities of the wrapper are removable, and not only listable. */
class IdentityRepositoryWrapperTest {

  private static final byte[] BLOB = Util.str2byte("not really a public key blob");

  @Test
  void removeRemovesACachedIdentity() {
    StubIdentityRepository delegate = new StubIdentityRepository();
    IdentityRepositoryWrapper wrapper = new IdentityRepositoryWrapper(delegate);
    StubIdentity identity = new StubIdentity();
    wrapper.add(identity);

    assertEquals(1, wrapper.getIdentities().size(), "the cached identity should be listed");

    assertTrue(wrapper.remove(BLOB.clone()));
    assertTrue(wrapper.getIdentities().isEmpty(), "the cached identity should be gone");
    assertTrue(identity.cleared, "the removed identity should have been cleared");
  }

  @Test
  void removeReportsFailureForAnUnknownIdentity() {
    IdentityRepositoryWrapper wrapper = new IdentityRepositoryWrapper(new StubIdentityRepository());

    assertFalse(wrapper.remove(Util.str2byte("some other blob")));
  }

  /** Removing an identity of the wrapped repository still reports what that repository says. */
  @Test
  void removeDelegatesForAnIdentityThatIsNotCached() {
    StubIdentityRepository delegate = new StubIdentityRepository();
    delegate.removeResult = true;
    IdentityRepositoryWrapper wrapper = new IdentityRepositoryWrapper(delegate);

    assertTrue(wrapper.remove(BLOB.clone()));
    assertEquals(1, delegate.removeCalls);
  }

  @Test
  void removeAllIdentitiesClearsTheCacheAndReportsTheDelegateResult() {
    StubIdentityRepository delegate = new StubIdentityRepository();
    delegate.removeAllResult = false;
    IdentityRepositoryWrapper wrapper = new IdentityRepositoryWrapper(delegate);
    wrapper.add(new StubIdentity());

    assertFalse(wrapper.removeAllIdentities(), "the refusal of the delegate should be reported");
    assertTrue(wrapper.getIdentities().isEmpty(), "the cache should be cleared regardless");
    assertEquals(1, delegate.removeAllCalls);
  }

  private static final class StubIdentityRepository implements IdentityRepository {
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
      return new Vector<>();
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
    public void removeAll() {}

    @Override
    public boolean removeAllIdentities() {
      removeAllCalls++;
      return removeAllResult;
    }
  }

  /** Not an IdentityFile, so IdentityRepositoryWrapper keeps it in its own cache. */
  private static final class StubIdentity implements Identity {
    boolean cleared;

    @Override
    public boolean setPassphrase(byte[] passphrase) {
      return true;
    }

    @Override
    public byte[] getPublicKeyBlob() {
      return BLOB.clone();
    }

    @Override
    public byte[] getSignature(byte[] data) {
      return null;
    }

    @Override
    public byte[] getSignature(byte[] data, String alg) {
      return null;
    }

    @Override
    public String getAlgName() {
      return "stub";
    }

    @Override
    public String getName() {
      return "stub";
    }

    @Override
    public boolean isEncrypted() {
      return false;
    }

    @Override
    public void clear() {
      cleared = true;
    }
  }
}
