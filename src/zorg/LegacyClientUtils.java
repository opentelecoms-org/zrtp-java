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
package zorg;

import zorg.platform.Platform;

/** 
 *  Original ZRTP reference implementation was not compatible with final RFC
 *  for ECDH key agreement. ZORG library has been developed keeping back-compatibility
 *  with libzrtp implementation.
 *  
 *  As long as ZRTP became accepted, other implementations appeared  (under GNU umbrella),
 *  which are RFC compatibile.
 *  
 *  Goal of this class is to detect legacy ZORG and libzrtp implementations as used
 *  inside PrivateGSM (ZRTP client developed by PrivateWave) and be able interoperate
 *  both with compliant clients and legacy ones.
 *   
 *  In the legacy client we add 32 leading bytes all zero to the DHResult
 *  to make it the same size as S60 client's DHResult
 *  only for interoperability reasons, although the size of DHResult
 *  as stated in Section 4.4.1.4 in ECDH P-256 mode is in fact 32 bytes
 *  as stated in Section 4.4.1.4 in ECDH P-384 mode is in fact 48 bytes
 */

public class LegacyClientUtils {

	
	/** Legacy Client send ZRTP.CLIENT_ID_LEGACY or a non-printable ClientId */
	public static boolean checkClientId(boolean isLegacyAttributeList, String farEndClientID) {
		if (ZRTP.CLIENT_ID_LEGACY.equals(farEndClientID)) 
			return true;
		
		if (ZRTP.CLIENT_ID_RFC.equals(farEndClientID)) 
			return false;
		
		boolean isPrintable = true;
		
		for (int i = 0; i < farEndClientID.length(); i++) {
			int singleChar = farEndClientID.charAt(i);
			if (singleChar < 32 || singleChar >= 127) {
				isPrintable = false;
			}
		}
		return !isPrintable && isLegacyAttributeList;
	}
	
	/** Legacy Client send 2 Hash type : S256 and S384*/
	public static boolean checkHash(Platform platform, byte[] aMsg, int hashPos, int hashCount) {
		if (hashCount != 2)
			return false;
		
		boolean result = (platform.getUtils().equals(HashType.SHA256.getType(), 0, aMsg, hashPos , 4)  &&
			    platform.getUtils().equals(HashType.SHA384.getType(), 0, aMsg, hashPos + 1 * 4, 4)); 
		
		return result;
	}

	/** Legacy Client send 2 Cipher : AES3 and AES1 */
	public static boolean checkCipher(Platform platform, byte[] aMsg, int cipherPos,
			int cipherCount) {
		if (cipherCount != 2)
			return false;
		
		boolean result = (platform.getUtils().equals(CipherType.AES3.getType(), 0, aMsg, cipherPos , 4)  &&
			    platform.getUtils().equals(CipherType.AES1.getType(), 0, aMsg, cipherPos + 1 * 4, 4));
		
		return result;
	}

	/** Legacy Client send 4 key agreement : EC38 EC25 DH3K DH2K */
	public static boolean checkKeyAgreement(Platform platform, byte[] aMsg, int keyPos,
			int keyCount) {
		if (keyCount != 4)
			return false;
		
		boolean result = (platform.getUtils().equals(KeyAgreementType.ECDH384.getType(), 0, aMsg, keyPos , 4)  &&
			    platform.getUtils().equals(KeyAgreementType.ECDH256.getType(), 0, aMsg, keyPos + 1 * 4, 4) &&
			    platform.getUtils().equals(KeyAgreementType.DH3K.getType(), 0, aMsg, keyPos + 2 * 4, 4) &&
			    platform.getUtils().equals(new byte[] { 'D', 'H', '2', 'k' }, 0, aMsg, keyPos + 3 * 4, 4));
		
		return result;
	}

	/** Legacy Client send 2 SAS agreement: B256 and B32 */
	public static boolean checkSasAgreement(Platform platform, byte[] aMsg, int sasPos,
			int sasCount) {
		if (sasCount != 2)
			return false;
		
		boolean result =  (platform.getUtils().equals(SasType.B256.getType(), 0, aMsg, sasPos , 4)  &&
			    platform.getUtils().equals(SasType.B32.getType(), 0, aMsg, sasPos + 1 * 4, 4));
		
		return result;
	}

}
