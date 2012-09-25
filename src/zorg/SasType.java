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

public class SasType {
	// Supported SAS types
	private final static int SAS_MODE_UNDEFINED = 0;
	private final static int SAS_MODE_B32 = 1;
	private final static int SAS_MODE_B256 = 2;

	private static final byte[] SAS_TYPE_UNDEFINED = {};
	private static final byte[] SAS_TYPE_B32 = { 'B', '3', '2', ' ' };
	private static final byte[] SAS_TYPE_B256 = { 'B', '2', '5', '6' };

	public static SasType UNDEFINED = new SasType(SAS_MODE_UNDEFINED);
	public static SasType B32 = new SasType(SAS_MODE_B32);
	public static SasType B256 = new SasType(SAS_MODE_B256);

	private static int getInt(byte b) {
		return (b + 0x100) % 0x100;
	}

	private int type;

	public SasType(int sasMode) {
		type = sasMode;
	}

	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		SasType other = (SasType) obj;
		if (type != other.type)
			return false;
		return true;
	}

	public String getShortAuthenticationStrings(byte[] sasHash) {
		StringBuffer sas = new StringBuffer();
		if (type == SAS_MODE_B32) {
			// Using method shown in ZRTP Spec, section 5.1.6
			String sasChars = "ybndrfg8ejkmcpqxot1uwisza345h769";
			// leftmost 20 bits
			final int bits = (getInt(sasHash[0]) << 12)
					| (getInt(sasHash[1]) << 4) | (getInt(sasHash[2]) >>> 4);
			for (int i = 0, shift = 27; i < 4; ++i, shift -= 5) {
				int n = (bits >>> shift) & 0x1F;
				sas.append(sasChars.charAt(n));
			}
		} else {
			sas.append(ZrtpStrings.PGP_WORDS_EVEN[getInt(sasHash[0])]);
			sas.append(" ");
			sas.append(ZrtpStrings.PGP_WORDS_ODD[getInt(sasHash[1])]);
		}
		return sas.toString();
	}

	public byte[] getType() {
		switch (type) {
		case SAS_MODE_B256:
			return SAS_TYPE_B256;
		case SAS_MODE_B32:
			return SAS_TYPE_B32;
		case SAS_MODE_UNDEFINED:
		default:
			return SAS_TYPE_UNDEFINED;
		}
	}

	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + type;
		return result;
	}
}
