/**
 * ZRTP.org is a ZRTP protocol implementation  
 * Copyright (C) 2012 - PrivateWave Italia S.p.A.
 * 
 * This  program  is free software:  you can  redistribute it and/or
 * modify  it  under  the terms  of  the  GNU Affero  General Public
 * License  as  published  by the  Free Software Foundation,  either 
 * version 3 of the License,  or (at your option) any later version.
 * 
 * This program is  distributed in  the hope that it will be useful,
 * but WITHOUT ANY WARRANTY;  without even  the implied  warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU 
 * Affero General Public License for more details.
 * 
 * You should have received a copy of the  GNU Affero General Public
 * License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 * 
 * For more information, please contact PrivateWave Italia S.p.A. at
 * address zorg@privatewave.com or http://www.privatewave.com 
 */
package zorg.platform.android;

import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import zorg.CryptoException;
import zorg.platform.CryptoUtils;
import zorg.platform.DiffieHellmanSuite;
import zorg.platform.Digest;
import zorg.platform.EncryptorSuite;
import zorg.platform.HMAC;
import zorg.platform.RandomGenerator;

public class AndroidCryptoUtils implements CryptoUtils {

	private RandomGenerator randomGenerator;

	/* (non-Javadoc)
	 * @see zorg.platform.CryptoUtils#aesDecrypt(byte[], int, int, byte[], byte[])
	 */
	@Override
	public byte[] aesDecrypt(byte[] data, int offset, int length, byte[] key,
			byte[] initVector) throws CryptoException {
		try {
			SecretKeySpec scs = new SecretKeySpec(key, "AES");
			Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding", "ZBC");
			IvParameterSpec iv = new IvParameterSpec(initVector);
			ByteArrayOutputStream baos = new ByteArrayOutputStream(length);
			cipher.init(Cipher.DECRYPT_MODE, scs, iv);
			CipherOutputStream out = new CipherOutputStream(baos, cipher);
			out.write(data, offset, length);
			out.close();
			baos.close();
			return baos.toByteArray();
		} catch (Exception e) {
			throw new CryptoException(e);
		}
	}

	/* (non-Javadoc)
	 * @see zorg.platform.CryptoUtils#aesEncrypt(byte[], byte[], byte[])
	 */
	@Override
	public byte[] aesEncrypt(byte[] data, byte[] key, byte[] initVector)
			throws CryptoException {
		try {
			SecretKeySpec scs = new SecretKeySpec(key, "AES");
			Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding", "ZBC");
			IvParameterSpec iv = new IvParameterSpec(initVector);
			cipher.init(Cipher.ENCRYPT_MODE, scs, iv);
			ByteArrayOutputStream baos = new ByteArrayOutputStream(data.length);
			CipherOutputStream out = new CipherOutputStream(baos, cipher);
			out.write(data, 0, data.length);
			out.close();
			baos.close();
			return baos.toByteArray();
		} catch (Exception e) {
			throw new CryptoException(e);
		}
	}

	/* (non-Javadoc)
	 * @see zorg.platform.CryptoUtils#calculateSHA256HMAC(byte[], int, int, byte[])
	 */
	@Override
	public byte[] calculateSHA256HMAC(byte[] data, int offset, int length,
			byte[] aKey) {
		return BCHmacAdapter.hmac(data, offset, length, aKey, "HmacSHA256");
	}

	/* (non-Javadoc)
	 * @see zorg.platform.CryptoUtils#calculateSHA384HMAC(byte[], int, int, byte[])
	 */
	@Override
	public byte[] calculateSHA384HMAC(byte[] data, int offset, int length,
			byte[] aKey) {
		return BCHmacAdapter.hmac(data, offset, length, aKey, "HmacSHA384");
	}

	/* (non-Javadoc)
	 * @see zorg.platform.CryptoUtils#createDHSuite()
	 */
	@Override
	public DiffieHellmanSuite createDHSuite() {
		return new BCDHSuite();
	}

	/* (non-Javadoc)
	 * @see zorg.platform.CryptoUtils#createDigestSHA1()
	 */
	@Override
	public Digest createDigestSHA1() {
		try {
			return new BCDigest(MessageDigest.getInstance("SHA1", "ZBC"));
		} catch (GeneralSecurityException e) {
			AndroidPlatform.getInstance().getLogger().logException(e.getMessage());
			return null;
		}
	}

	/* (non-Javadoc)
	 * @see zorg.platform.CryptoUtils#createDigestSHA256()
	 */
	@Override
	public Digest createDigestSHA256() {
		try {
			return new BCDigest(MessageDigest.getInstance("SHA256", "ZBC"));
		} catch (GeneralSecurityException e) {
			AndroidPlatform.getInstance().getLogger().logException(e.getMessage());
			return null;
		}
	}

	/* (non-Javadoc)
	 * @see zorg.platform.CryptoUtils#createDigestSHA384()
	 */
	@Override
	public Digest createDigestSHA384() {
		try {
			return new BCDigest(MessageDigest.getInstance("SHA384", "ZBC"));
		} catch (GeneralSecurityException e) {
			AndroidPlatform.getInstance().getLogger().logException(e.getMessage());
			return null;
		}
	}

	/* (non-Javadoc)
	 * @see zorg.platform.CryptoUtils#createEncryptorSuite(byte[], byte[])
	 */
	@Override
	public EncryptorSuite createEncryptorSuite(byte[] key, byte[] initVector)
			throws CryptoException {
		return new BCEncryptorSuite(key, initVector);
	}

	/* (non-Javadoc)
	 * @see zorg.platform.CryptoUtils#createHMACSHA1(byte[])
	 */
	@Override
	public HMAC createHMACSHA1(byte[] hmacKey) throws CryptoException {
		try {
			return new BCHmacAdapter(hmacKey, "SHA1");
		} catch (Exception e) {
			AndroidPlatform.getInstance().getLogger().logException(e.getMessage());
			return null;
		}
	}

	/* (non-Javadoc)
	 * @see zorg.platform.CryptoUtils#getRandomGenerator()
	 */
	@Override
	public RandomGenerator getRandomGenerator() {
		return randomGenerator;
	}

	/* (non-Javadoc)
	 * @see zorg.platform.CryptoUtils#setRandomGenerator(zorg.platform.RandomGenerator)
	 */
	@Override
	public void setRandomGenerator(RandomGenerator r) {
		randomGenerator = r;
	}

}
