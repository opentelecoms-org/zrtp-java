package zorg.platform.j2se;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

import zorg.CryptoException;
import zorg.platform.EncryptorSuite;


public class EncryptorSuiteImpl implements EncryptorSuite {
	
	private static final String CIPHER_ALGORITHM = "AES";

	SecretKeySpec skeySpec;
	Cipher cipher;
	SecureRandom secureRandom;
	
	public EncryptorSuiteImpl(byte[] key, byte[] initVector) throws zorg.CryptoException {
		try {
			skeySpec = new SecretKeySpec(key, "AES");
			cipher = Cipher.getInstance(CIPHER_ALGORITHM);
			secureRandom = SecureRandom.getInstance(CryptoUtilsImpl.DEFAULT_RANDOM_ALGORITHM);
			secureRandom.setSeed(initVector);
			cipher.init(Cipher.ENCRYPT_MODE, skeySpec, secureRandom);
		} catch (Exception ex) {
			ex.printStackTrace();
			throw new CryptoException(ex);
		}
	}

	public void encrypt(byte[] aIV, byte[] buffer) throws CryptoException {
		try {
			byte[] _result = cipher.doFinal(aIV, 0, aIV.length);
			for(int i = 0; i < buffer.length; i++)
				buffer[i] = _result[i];
		} catch (Exception e) {
			throw new CryptoException(e);
		}
	}

	public byte[] encryptIV_for_prf(byte[] IV) throws CryptoException {
		try {
			Cipher _cipher = Cipher.getInstance(CIPHER_ALGORITHM);
			_cipher.init(Cipher.ENCRYPT_MODE, skeySpec, secureRandom);
			byte[] _result = _cipher.doFinal(IV, 0, 16);
			byte[] result = _result;
			if(result.length > 16) {
				result = new byte[16];
				for(int i = 0; i < 16; i++)
					result[i] = _result[i];
			}
			return result;
		} catch (Exception e) {
			throw new CryptoException(e);
		}	
	}

}
