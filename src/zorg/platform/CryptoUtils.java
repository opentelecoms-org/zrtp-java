/**
 * ZRTP.org is a ZRTP protocol implementation  
 * Copyright (C) 2010 - PrivateWave Italia S.p.A.
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
package zorg.platform;

import zorg.CryptoException;

/**
 * Interface to group all crypto and digest related functions
 */
public interface CryptoUtils {

	/**
	 * AES decrypt data, using key and initialization vector
	 * 
	 * @param data
	 *            encrypted data
	 * @param offset
	 *            decrypt starting at offset
	 * @param length
	 *            decrypt lenth byte
	 * @param key
	 *            AEES key
	 * @param initVector
	 *            initialization vector
	 * @return plain data
	 * @throws CryptoException
	 */
	byte[] aesDecrypt(byte[] data, int offset, int length, byte[] key,
			byte[] initVector) throws CryptoException;

	/**
	 * AES encrypt data, using key and initialization vector
	 * 
	 * @param data
	 *            clear text
	 * @param key
	 *            AES key
	 * @param initVector
	 *            initialization vector
	 * @return encrypted data
	 * @throws CryptoException
	 */
	byte[] aesEncrypt(byte[] data, byte[] key, byte[] initVector)
			throws CryptoException;

	/** calculate HMAC-SHA-256 with passed in digest */
	byte[] calculateSHA256HMAC(byte[] data, int offset, int length, byte[] aKey);

	/** calculate HMAC-SHA-384 with passed in digest */
	byte[] calculateSHA384HMAC(byte[] data, int offset, int length, byte[] aKey);

	/**
	 * Create a Diffie Hellman suite
	 */
	DiffieHellmanSuite createDHSuite();

	/** create a SHA-1 Digest */
	Digest createDigestSHA1();

	/** create a SHA-256 Digest */
	Digest createDigestSHA256();

	/** create a SHA-384 Digest */
	Digest createDigestSHA384();

	/**
	 * Create AES encryptor suite for CBC and CFB encryption
	 * 
	 * @param key
	 *            AES key
	 * @param initVector
	 *            initialization vector
	 * @return
	 * @throws CryptoException
	 */
	EncryptorSuite createEncryptorSuite(byte[] key, byte[] initVector)
			throws CryptoException;

	/** create an HMAC-SHA1 initialized with the given key */
	HMAC createHMACSHA1(byte[] hmacKey) throws CryptoException;

	/**
	 * Return the a Random Generator. Great care should be put in choosing the a
	 * good source of entropy
	 */
	RandomGenerator getRandomGenerator();

	/**
	 * Set the Random Generator
	 */	
	void setRandomGenerator(RandomGenerator r);
	
}