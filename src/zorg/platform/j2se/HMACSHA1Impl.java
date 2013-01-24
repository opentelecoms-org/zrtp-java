package zorg.platform.j2se;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

import zorg.CryptoException;
import zorg.platform.HMAC;


public class HMACSHA1Impl implements HMAC {
	
	byte[] hmacKey;
	SecretKeySpec secret;
	Mac mac;
	
	public HMACSHA1Impl(byte[] hmacKey) throws CryptoException {
		try {
			this.hmacKey = hmacKey;
			mac = Mac.getInstance("HmacSHA1");
			secret = new SecretKeySpec(hmacKey, mac.getAlgorithm());
			mac.init(secret);
		} catch (Exception e) {
			throw new CryptoException(e);
		}
	}

	@Override
	public void reset() throws CryptoException {
		mac.reset();
	}

	@Override
	public void update(byte[] data, int offset, int length) {
		mac.update(data, offset, length);
	}

	@Override
	public void update(byte[] data) throws CryptoException {
		update(data, 0, data.length);
	}

	@Override
	public int getMAC(byte[] data, int offset) throws CryptoException {
		try {
			mac.doFinal(data, offset);
		} catch (Exception e) {
			throw new CryptoException(e);
		}
		return mac.getMacLength();
	}

}
