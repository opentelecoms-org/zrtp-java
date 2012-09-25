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

public class CipherType {

	// Cipher type in use
	private final static int CIPHER_UNDEFINED = 0;
	private final static int CIPHER_AES1 = 1;
	private final static int CIPHER_AES3 = 2;

	private static final byte[] CIPHER_TYPE_UNDEFINED = {};
	private static final byte[] CIPHER_TYPE_AES1 = { 'A', 'E', 'S', '1' };
	private static final byte[] CIPHER_TYPE_AES3 = { 'A', 'E', 'S', '3' };

	public static final CipherType UNDEFINED = new CipherType(CIPHER_UNDEFINED);
	public static final CipherType AES1 = new CipherType(CIPHER_AES1);
	public static final CipherType AES3 = new CipherType(CIPHER_AES3);

	private int type;

	public CipherType(int cipherType) {
		type = cipherType;
	}

	public byte[] getType() {
		switch (type) {
		case CIPHER_AES1:
			return CIPHER_TYPE_AES1;
		case CIPHER_AES3:
			return CIPHER_TYPE_AES3;
		case CIPHER_UNDEFINED:
		default:
			return CIPHER_TYPE_UNDEFINED;
		}
	}

}
