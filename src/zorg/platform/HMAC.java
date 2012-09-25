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
 * Generic interface for HMAC
 */
public interface HMAC {

	/**
	 * Write MAC for all passed data since last reset
	 * 
	 * @param data
	 *            write MAC inside this buffer
	 * @param offset
	 *            write starting at offset
	 * @return number of bytes written
	 * @throws CryptoException
	 */
	int getMAC(byte[] data, int offset) throws CryptoException;

	/**
	 * Reset HMAC
	 * 
	 * @throws CryptoException
	 */
	void reset() throws CryptoException;

	/**
	 * Update HMAC with passed buffer
	 * 
	 * @param data
	 * @throws CryptoException
	 */
	void update(byte[] data) throws CryptoException;

	/**
	 * Update HMAC with data
	 * 
	 * @param data
	 *            buffer with data to be uset
	 * @param offset
	 *            start digesting data at offset
	 * @param length
	 *            use only length bytes
	 */
	void update(byte[] data, int offset, int length);

}
