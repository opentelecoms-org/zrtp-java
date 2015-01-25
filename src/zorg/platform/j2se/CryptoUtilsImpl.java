package zorg.platform.j2se;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import zorg.CryptoException;
import zorg.platform.DiffieHellmanSuite;
import zorg.platform.Digest;
import zorg.platform.EncryptorSuite;
import zorg.platform.HMAC;
import zorg.platform.RandomGenerator;

import com.sun.crypto.provider.AESParameters;


public class CryptoUtilsImpl implements zorg.platform.CryptoUtils {
	
	public static final String DEFAULT_RANDOM_ALGORITHM = "SHA1PRNG";
	
	public CryptoUtilsImpl() {
		
	}

	private Digest makeDigestImpl(DigestType digestType) {
		try {
			return new DigestImpl(digestType);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			throw new RuntimeException("Failed to create digest: " + digestType + ": " + e.getClass().getName() + ": " + e.getMessage());
		}
	}
	
	public Digest createDigestSHA1() {
		return makeDigestImpl(DigestType.SHA1);
	}
	
	public Digest createDigestSHA256() {
		return makeDigestImpl(DigestType.SHA256);
	}

	public Digest createDigestSHA384() {
		return makeDigestImpl(DigestType.SHA384);
	}

	public byte[] calculateSHA256HMAC(byte[] data, int offset, int length,
			byte[] aKey) {
		return calculateHMAC(DigestType.SHA256, data, offset, length, aKey);
	}

	public byte[] calculateSHA384HMAC(byte[] data, int offset, int length,
			byte[] aKey) {
		return calculateHMAC(DigestType.SHA384, data, offset, length, aKey);
	}

	private byte[] calculateHMAC(DigestType digestType, byte[] data, int offset,
			int length, byte[] aKey) {
		try {
			Mac mac = Mac.getInstance(digestType.getJCEHmacName());
			SecretKeySpec key = new SecretKeySpec(aKey, mac.getAlgorithm());
			mac.init(key);
			mac.update(data, offset, length);
			return mac.doFinal();
		} catch (Exception e) {
			e.printStackTrace();
			throw new RuntimeException("Failed to calc hmac " + digestType + e.getClass().getName() + ": " + e.getMessage());
		}
	}

	public HMAC createHMACSHA1(byte[] hmacKey) throws CryptoException {
		return new HMACSHA1Impl(hmacKey);
	}

	public RandomGenerator getRandomGenerator() {
		return new RandomGeneratorImpl();
	}
	
	final static String CIPHER_ALGORITHM_CFB = "AES/CFB64/NoPadding";

	public byte[] aesEncrypt(byte[] data, byte[] key, byte[] initVector)
			throws CryptoException {
		try {
			SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
			Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM_CFB);
			//SecureRandom secureRandom = SecureRandom.getInstance(CryptoUtilsImpl.DEFAULT_RANDOM_ALGORITHM);
			//secureRandom.setSeed(initVector);
			IvParameterSpec ivSpec = new IvParameterSpec(initVector);
			cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
			return cipher.doFinal(data);
		} catch (Exception e) {
			throw new CryptoException(e);
		}
	}

	public byte[] aesDecrypt(byte[] data, int offset, int length, byte[] key,
			byte[] initVector) throws CryptoException {
		try {
			SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
			Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM_CFB);
			//SecureRandom secureRandom = SecureRandom.getInstance(CryptoUtilsImpl.DEFAULT_RANDOM_ALGORITHM);
			//secureRandom.setSeed(initVector);
			IvParameterSpec ivSpec = new IvParameterSpec(initVector);
			cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
			return cipher.doFinal(data, offset, length);
		} catch (Exception e) {
			throw new CryptoException(e);
		}
	}

	public DiffieHellmanSuite createDHSuite() {
		return new DiffieHellmanSuiteImpl();
	}

	public EncryptorSuite createEncryptorSuite(byte[] key, byte[] initVector)
			throws CryptoException {
		return new EncryptorSuiteImpl(key, initVector);
	}

	public void setRandomGenerator(RandomGenerator r) {
		// TODO Auto-generated method stub
		
	}

}
