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

import java.security.DigestException;
import java.security.MessageDigest;

import zorg.platform.Digest;

public class BCDigest implements Digest {

	private MessageDigest digest;

	public BCDigest(MessageDigest digest) {
		this.digest = digest;
	}

	@Override
	public byte[] getDigest() {
		return digest.digest();
	}

	@Override
	public int getDigest(byte[] buffer, int offset, boolean reset) {
		try {
			return digest.digest(buffer, offset, buffer.length - offset);
		} catch (DigestException e) {
			e.printStackTrace();
			return 0;
		}
	}

	@Override
	public int getDigestLength() {
		return digest.getDigestLength();
	}

	@Override
	public void update(byte[] buffer) {
		if (buffer == null)
			return;
		update(buffer, 0, buffer.length);
	}

	@Override
	public void update(byte[] buffer, int offset, int length) {
		digest.update(buffer, offset, length);
	}

}
