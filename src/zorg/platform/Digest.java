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

/**
 * Generic interface over different digest algorithms
 */
public interface Digest {

	/** returns calculated digest */
	public byte[] getDigest();

	/** insert digest into buffer at offeset and optionallu reset digest */
	public int getDigest(byte[] buffer, int offset, boolean reset);

	/** returns digest length */
	public int getDigestLength();

	/** update digest with buffer data */
	public void update(byte[] buffer);

	/** update digest with data in buffer at offset for length bytes */
	public void update(byte[] buffer, int offset, int length);

}
