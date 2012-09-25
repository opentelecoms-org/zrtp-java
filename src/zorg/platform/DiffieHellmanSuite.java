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

import zorg.KeyAgreementType;
import zorg.ZrtpException;

/**
 * Interface for Diffie Hellman calculation. It supports: * DH 3K * ECDH-256 *
 * ECDH-384
 */
public interface DiffieHellmanSuite {

	/** reset keys */
	void clear();

	/**
	 * Diffie Hellman key calculation
	 * 
	 * @param aMsg - DHPartX message
	 * @param offset
	 * @param isLegacyClient - true if the farSide is a legacy ZRTP client
	 * @return DH calculation
	 * @throws ZrtpException
	 */
	byte[] getDhResult(byte[] aMsg, int offset, boolean isLegacyClient) throws ZrtpException;

	/** choose DH algorithm */
	void setAlgorithm(KeyAgreementType dhMode);

	/**
	 * Set the internal logger
	 * 
	 * @param logger a ZrtpLogger implementation
	 */
	void setLogger(ZrtpLogger logger);

	/**
	 * extratc public key
	 * 
	 * @param data
	 *            public key is written to thiss buffer
	 * @param offset
	 *            public written at offest
	 * @throws ZrtpException
	 */
	void writePublicKey(byte[] data, int offset) throws ZrtpException;
}
