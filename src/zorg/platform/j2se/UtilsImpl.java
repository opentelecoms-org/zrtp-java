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

import java.util.Arrays;

import zorg.platform.LongSortedVector;
import zorg.platform.Utils;

public class AndroidUtils implements Utils {

	@Override
	public String byteToHexString(byte[] buffer) {
		if (buffer == null)
			return "<NULL>";
		return byteToHexString(buffer, 0, buffer.length);
	}


	@Override
	public String byteToHexString(byte[] b, int offset, int len) {
		if (b == null) {
			return (new String(""));
		}
		// if (len>32) len = 32;
		char[] cArray = new char[len * 2];
		for (int i = 0; i < len; i++) {
			byte hex = (byte) ((b[offset + i] >> 4) & 0x0f);
			char ch;
			if (hex > 0x09) {
				ch = (char) (hex - 0x0A + 'A');
			} else {
				ch = (char) (hex + '0');
			}
			cArray[2 * i] = ch;
			hex = (byte) (b[offset + i] & 0x0f);
			if (hex > 0x09) {
				ch = (char) (hex - 0x0A + 'A');
			} else {
				ch = (char) (hex + '0');
			}
			cArray[1 + (2 * i)] = ch;
		}
		String s = new String(cArray);
		return s;
	}

	@Override
	public byte[] copy(byte[] data) {
		if (data == null)
			return null;
		byte[] copy = new byte[data.length];
		System.arraycopy(data, 0, copy, 0, data.length);
		return copy;
	}

	@Override
	public LongSortedVector createSortedVector() {
		return new SortedVector();
	}

	@Override
	public boolean equals(byte[] array1, int offset1, byte[] array2,
			int offset2, int length) {
		for (int i = 0; i < length; i++) {
			if (array1[offset1 + i] != array2[offset2 + i])
				return false;
		}
		return true;
	}

	@Override
	public int getInt(byte[] data, int offset, int length) {
		return (int) getLong(data, offset, offset + length);
	}

	private long getLong(byte[] data, int begin, int end) {
		long n = 0;
		for (; begin < end; begin++) {
			n <<= 8;
			n += 0xFF & data[begin];
		}
		return n;
	}

	@Override
	public void zero(byte[] data) {
		Arrays.fill(data, (byte) 0);
	}

}
