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
package zorg;

public class HashType {

	private final static int HASH_UNDEFINED = 0;
	private final static int HASH_SHA_256 = 1;
	private final static int HASH_SHA_384 = 2;

	private static final byte[] HASH_TYPE_UNDEFINED = {};
	private static final byte[] HASH_TYPE_256 = { 'S', '2', '5', '6' };
	private static final byte[] HASH_TYPE_384 = { 'S', '3', '8', '4' };

	public static HashType UNDEFINED = new HashType(HASH_UNDEFINED);
	public static HashType SHA256 = new HashType(HASH_SHA_256);
	public static HashType SHA384 = new HashType(HASH_SHA_384);

	private int numType;

	private String name;

	public HashType(int hashType) {
		numType = hashType;
		name = new String(getType());
	}

	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		HashType other = (HashType) obj;
		if (numType != other.numType)
			return false;
		return true;
	}

	public int getLength() {
		switch (numType) {
		case HASH_SHA_256:
			return 256;
		case HASH_SHA_384:
			return 384;
		case HASH_UNDEFINED:
		default:
			return 0;
		}
	}

	public byte[] getType() {
		switch (numType) {
		case HASH_SHA_256:
			return HASH_TYPE_256;
		case HASH_SHA_384:
			return HASH_TYPE_384;
		case HASH_UNDEFINED:
		default:
			return HASH_TYPE_UNDEFINED;
		}
	}

	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + numType;
		return result;
	}

	public String toString() {
		return name;
	}

}
