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

public class KeyAgreementType {

	// Supported DH modes
	public final static int DH_MODE_UNDEFINED = 0;
	public final static int DH_MODE_DH3K = 1;
	public final static int DH_MODE_EC38 = 2;
	public final static int DH_MODE_EC25 = 3;

	private static final byte[] KEY_TYPE_EC25 = { 'E', 'C', '2', '5' };
	private static final byte[] KEY_TYPE_EC38 = { 'E', 'C', '3', '8' };
	private static final byte[] KEY_TYPE_DH3K = { 'D', 'H', '3', 'k' };

	public static final KeyAgreementType DH3K = new KeyAgreementType(
			DH_MODE_DH3K);
	public static final KeyAgreementType ECDH256 = new KeyAgreementType(
			DH_MODE_EC25);
	public static final KeyAgreementType ECDH384 = new KeyAgreementType(
			DH_MODE_EC38);

	public final int keyType;

	public final HashType hash;

	public final int pvLengthInWords;

	public KeyAgreementType(int keyAgreementType) {
		this.keyType = keyAgreementType;
		switch (keyType) {
		case DH_MODE_EC25:
			hash = HashType.SHA256;
			pvLengthInWords = 16;
			break;
		case DH_MODE_EC38:
			hash = HashType.SHA384;
			pvLengthInWords = 24;
			break;
		case DH_MODE_DH3K:
		default:
			hash = HashType.SHA256;
			pvLengthInWords = 96;
			break;
		}
	}

	public byte[] getType() {
		switch (keyType) {
		case DH_MODE_EC25:
			return KEY_TYPE_EC25;
		case DH_MODE_EC38:
			return KEY_TYPE_EC38;
		case DH_MODE_DH3K:
		default:
			return KEY_TYPE_DH3K;
		}
	}

	public String toString() {
		return new String(getType());
	}
}
