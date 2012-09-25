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

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import zorg.CryptoException;
import zorg.platform.EncryptorSuite;

public class BCEncryptorSuite implements EncryptorSuite {

	private Cipher cipher;
	private IvParameterSpec iv;
	private SecretKeySpec scs;

	public BCEncryptorSuite(byte[] key, byte[] initVector)
			throws CryptoException {
		try {
			scs = new SecretKeySpec(key, "AES");
			cipher = Cipher.getInstance("AES/CBC/NoPadding", "ZBC");
			iv = new IvParameterSpec(initVector);
			cipher.init(Cipher.ENCRYPT_MODE, scs, iv);
		} catch (Exception e) {
			throw new CryptoException(e);
		}
	}

	@Override
	public void encrypt(byte[] aIV, byte[] buffer) throws CryptoException {
		try {
			cipher.init(Cipher.ENCRYPT_MODE, scs, iv);
			byte[] res = cipher.doFinal(aIV);
			System.arraycopy(res, 0, buffer, 0, res.length);
		} catch (Exception e) {
			throw new CryptoException(e);
		}
	}

	@Override
	public byte[] encryptIV_for_prf(byte[] IV) throws CryptoException {
		try {
			Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "ZBC");
			cipher.init(Cipher.ENCRYPT_MODE, scs, iv);
			return cipher.doFinal(IV, 0, 16);
		} catch (Exception e) {
			throw new CryptoException(e);
		}
	}

}
