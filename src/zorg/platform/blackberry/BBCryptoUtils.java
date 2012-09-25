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
package zorg.platform.blackberry;

import java.io.ByteArrayInputStream;

import net.rim.device.api.crypto.AESEncryptorEngine;
import net.rim.device.api.crypto.AESKey;
import net.rim.device.api.crypto.CFBDecryptor;
import net.rim.device.api.crypto.CFBEncryptor;
import net.rim.device.api.crypto.CryptoTokenException;
import net.rim.device.api.crypto.CryptoUnsupportedOperationException;
import net.rim.device.api.crypto.HMAC;
import net.rim.device.api.crypto.HMACKey;
import net.rim.device.api.crypto.InitializationVector;
import net.rim.device.api.crypto.SHA1Digest;
import net.rim.device.api.crypto.SHA256Digest;
import net.rim.device.api.crypto.SHA384Digest;
import net.rim.device.api.io.NoCopyByteArrayOutputStream;
import zorg.CryptoException;
import zorg.ZrtpException;
import zorg.platform.CryptoUtils;
import zorg.platform.DiffieHellmanSuite;
import zorg.platform.Digest;
import zorg.platform.EncryptorSuite;
import zorg.platform.RandomGenerator;

public class BBCryptoUtils implements CryptoUtils {

	public static RandomGenerator randomGenerator;

	public void setRandomGenerator(RandomGenerator g) {
		randomGenerator = g; 
	}
	
	public Digest createDigestSHA1() {
	    return new DigestBBAdapter(new SHA1Digest());
    }

	public Digest createDigestSHA256() {
	    return new DigestBBAdapter(new SHA256Digest());
    }

	public Digest createDigestSHA384() {
	    return new DigestBBAdapter(new SHA384Digest());
    }

	public byte[] calculateSHA256HMAC(byte[] data, int offset, int length, byte[] aKey) {
		return createSHAHMAC(new SHA256Digest(), data, offset, length, aKey);
	}
	
	public byte[] calculateSHA384HMAC(byte[] data, int offset, int length, byte[] aKey) {
		return createSHAHMAC(new SHA384Digest(), data, offset, length, aKey);
	}
	
	private byte[] createSHAHMAC(net.rim.device.api.crypto.Digest digest, byte[] data, int offset, int length, byte[] aKey) {
        HMACKey hKey = new HMACKey(aKey);
        int digestLen = digest.getDigestLength();
        byte[] auth = new byte[digestLen];
        try {
            HMAC hmac = new HMAC(hKey, digest);
            hmac.update(data, offset, length);
            hmac.getMAC(auth, 0);
        } catch (CryptoTokenException tokEx) {
            tokEx.printStackTrace();
        } catch (CryptoUnsupportedOperationException opEx) {
            opEx.printStackTrace();
        }
        // If either of the above throws occur, will still return a non-null array
        // This will result in current message being invalid but will allow protocol to recover
        // if caused by a transient problem
        
        return auth;
    }

	public RandomGenerator getRandomGenerator() {
	    return randomGenerator;
    }

	public byte[] aesEncrypt(byte[] data, byte[] key, byte[] initVector) throws CryptoException {
        try {
            AESKey aesKey = new AESKey(key);
            NoCopyByteArrayOutputStream encryptedOs = new NoCopyByteArrayOutputStream();
            CFBEncryptor encryptor;
	        encryptor = new CFBEncryptor(new AESEncryptorEngine( aesKey ), new InitializationVector(initVector), encryptedOs, false);
	        encryptor.write(data, 0, data.length);
	        encryptor.close();
	        return encryptedOs.toByteArray();
        } catch (Exception e) {
	        throw new ZrtpException(e);
        }
    }

	public byte[] aesDecrypt(byte[] data, int offset, int len, byte[] key, byte[] initVector) throws CryptoException {
        try {
            byte[] plainBytes = new byte[40];  //10 words
    		AESKey aeskey = new AESKey(key);
            ByteArrayInputStream encryptedOs = new ByteArrayInputStream(data, offset, len);    //from byte 36
            CFBDecryptor decryptor = new CFBDecryptor(new AESEncryptorEngine(aeskey), new InitializationVector(initVector), encryptedOs, false);
            decryptor.read(plainBytes, 0, plainBytes.length);
            return plainBytes;
        } catch (Exception e) {
	       throw new ZrtpException(e);
        }
    }

	public DiffieHellmanSuite createDHSuite() {
	    return new DHSuite();
    }

	public zorg.platform.HMAC createHMACSHA1(byte[] hmacKey) throws CryptoException {
		try  {
			HMACKey key = new HMACKey(hmacKey);
			HMAC hmac = new HMAC(key, new SHA1Digest());
			return new HMACBBAdaptor(hmac);
		} catch (Exception e) {
			throw new CryptoException(e);
		}
    }

	public EncryptorSuite createEncryptorSuite(byte[] key, byte[] initVector) throws CryptoException {
	    return new BBEncryptorSuite(key, initVector);
    }
}
