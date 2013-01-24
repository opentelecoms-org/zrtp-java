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

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import zorg.CryptoException;
import zorg.platform.HMAC;

public class BCHmacAdapter implements HMAC {
	
	private Mac hmac;

	public BCHmacAdapter(byte[] hmacKey, String hashAlgorithm) {
		SecretKey key = new SecretKeySpec(hmacKey, "Hmac" + hashAlgorithm);
		try {
			hmac = Mac.getInstance("Hmac" + hashAlgorithm, "ZBC");
			hmac.init(key);
		} catch (Exception e) {
			AndroidPlatform.getInstance().getLogger().logException(e.getMessage());
		}
	}
	

	public static byte[] hmac(byte[] data, int offset, int length, byte[] aKey,
			String digestAlgorithm) {
		SecretKey key = new SecretKeySpec(aKey, digestAlgorithm);
		try {
			Mac hmac = Mac.getInstance(digestAlgorithm, "ZBC");
			hmac.init(key);
			hmac.update(data, offset, length);
			byte[] res = new byte[hmac.getMacLength()];
			hmac.doFinal(res, 0);
			return res;
		} catch (Exception e) {
			AndroidPlatform.getInstance().getLogger().logException(e.getMessage());
			return null;
		}
	}

	@Override
	public int getMAC(byte[] data, int offset) throws CryptoException {
		try {
			hmac.doFinal(data, offset);
			return hmac.getMacLength();
		} catch (Exception e) {
			throw new CryptoException(e);
		}
	}

	@Override
	public void reset() throws CryptoException {
		hmac.reset();
	}

	@Override
	public void update(byte[] data) throws CryptoException {
		if (data == null)
			return;
		hmac.update(data, 0, data.length);
	}

	@Override
	public void update(byte[] data, int offset, int length) {
		hmac.update(data, offset, length);
	}
}
