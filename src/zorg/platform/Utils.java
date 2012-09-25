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
 * Interface of platform specific utility functions
 */
public interface Utils {

	/**
	 * Returns an hex representation of buffer
	 */
	String byteToHexString(byte[] buffer);

	/**
	 * Returns an hex representation of a part of buffer
	 * 
	 * @param buffer
	 *            data to be converted to hex form
	 * @param offset
	 *            start at offset
	 * @param length
	 *            format length bytes
	 * @return
	 */
	String byteToHexString(byte[] buffer, int offset, int length);

	/**
	 * Returns a byte array copy of the argument
	 */
	byte[] copy(byte[] data);

	/**
	 * Create a Sorting Vector of Long objects
	 */
	LongSortedVector createSortedVector();

	/** compare two byte arrays */
	boolean equals(byte[] array1, int offset1, byte[] array2, int offset2,
			int length);

	/**
	 * Extract a int from a byte array
	 * 
	 * @param data
	 * @param offset
	 * @param length
	 * @return
	 */
	int getInt(byte[] data, int begin, int end);

	/**
	 * set to zero the byte array passed
	 */
	void zero(byte[] data);
}
