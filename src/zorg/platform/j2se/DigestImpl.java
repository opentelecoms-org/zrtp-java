package zorg.platform.j2se;

import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import zorg.platform.Digest;


public class DigestImpl implements Digest {
	
	MessageDigest md;
	
	public DigestImpl(DigestType digestType) throws NoSuchAlgorithmException {
		md = MessageDigest.getInstance(digestType.getJCEName());
	}

	@Override
	public int getDigestLength() {
		return md.getDigestLength();
	}

	@Override
	public void update(byte[] buffer) {
		md.update(buffer);
	}

	@Override
	public void update(byte[] buffer, int offset, int length) {
		md.update(buffer, offset, length);
	}

	@Override
	public byte[] getDigest() {
		return md.digest();
	}

	@Override
	public int getDigest(byte[] buffer, int offset, boolean reset) {
		// FIXME - remove the `reset' flag?  is it possible on every platform?
		//  is there a performance gain?  Can we cache digest objects for re-use?
		//if(!reset)
		//	throw new RuntimeException("Can't getDigest() without resetting");
		int len = getDigestLength();
		try {
			md.digest(buffer, offset, len);
		} catch (DigestException e) {
			e.printStackTrace();
			return -1;
		}
		return len;
	}

}
