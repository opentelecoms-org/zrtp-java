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

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import net.rim.device.api.crypto.AESEncryptorEngine;
import net.rim.device.api.crypto.AESKey;
import net.rim.device.api.crypto.BlockEncryptor;
import net.rim.device.api.crypto.CBCEncryptorEngine;
import net.rim.device.api.crypto.CryptoException;
import net.rim.device.api.crypto.CryptoTokenException;
import net.rim.device.api.crypto.InitializationVector;
import zorg.platform.EncryptorSuite;

public class BBEncryptorSuite implements EncryptorSuite {
    
    private AESEncryptorEngine engine;  // Encryptor components created at session start for tx encryption
    private InitializationVector initVector;
    private CBCEncryptorEngine cbcEngine;

    public BBEncryptorSuite(byte[] key, byte[] initVector) throws zorg.CryptoException {
        try {
            AESKey aesKey = new AESKey(key);
	        engine = new AESEncryptorEngine(aesKey);
	        this.initVector = new InitializationVector(initVector);
	        cbcEngine = new CBCEncryptorEngine(engine, this.initVector);
        } catch (CryptoException e) {
        	throw new zorg.CryptoException(e);
        }
    }

	public void encrypt(byte[] aIV, byte[] iTxEncOut) throws zorg.CryptoException {
        try {
        	cbcEngine.setIV(initVector);
	        cbcEngine.encrypt(aIV, 0, iTxEncOut, 0);
        } catch (CryptoTokenException e) {
        	throw new zorg.CryptoException(e);
        }
    }
   
	public byte[] encryptIV_for_prf(byte[] data) throws zorg.CryptoException {
        CBCEncryptorEngine enc = new CBCEncryptorEngine(engine, initVector);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        BlockEncryptor encryptor = new BlockEncryptor(enc, baos);
        try {
	        encryptor.write(data, 0, 16);
	        baos.close();
        } catch (IOException e) {
        	throw new zorg.CryptoException(e);
        }
        return baos.toByteArray();
    }

}
