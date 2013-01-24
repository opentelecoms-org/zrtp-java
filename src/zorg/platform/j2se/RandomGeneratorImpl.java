package zorg.platform.j2se;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import zorg.platform.RandomGenerator;


public class RandomGeneratorImpl implements RandomGenerator {
	
	SecureRandom sr;
	
	public RandomGeneratorImpl() {
		try {
			sr = SecureRandom.getInstance(CryptoUtilsImpl.DEFAULT_RANDOM_ALGORITHM);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			throw new RuntimeException("Failed to get random number generator: " +
					CryptoUtilsImpl.DEFAULT_RANDOM_ALGORITHM +
					e.getClass().getName() + ": " + e.getMessage());
		}
	}

	@Override
	public void getBytes(byte[] data) {
		sr.nextBytes(data);
	}

	@Override
	public void getBytes(byte[] data, int offset, int length) {
		byte[] _data = new byte[length];
		getBytes(_data);
		for(int i = 0; i < _data.length; i++)
			data[offset + i] = _data[i];
	}

	@Override
	public byte[] getBytes(int length) {
		byte[] data = new byte[length];
		getBytes(data);
		return data;
	}

	@Override
	public int getInt() {
		return sr.nextInt();
	}

	@Override
	public byte getByte() {
		byte[] b = new byte[1];
		getBytes(b);
		return b[0];
	}

	@Override
	public void seedUsingPcmAudio(byte[] mEntropyBytes) {
		// FIXME
	}

	@Override
	public boolean isInitialized() {
		return true;
	}

}
