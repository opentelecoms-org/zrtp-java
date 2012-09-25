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
 * Listener for ZRTP related events
 */
public interface ZrtpListener {

	/**
	 * Notification from key generator that exchange is completed and data can
	 * be received.
	 * 
	 * When ZRTP acts as the initiator, we don't have to wait for Conf2Ack,
	 * successfully authenticated media packets act as Conf2Ack. Therefore this
	 * function is detangled from the actual session completion.
	 * 
	 * @param txMasterKey
	 *            Master Key to be used for encrypting transmitted packets
	 * @param txMasterSalt
	 *            Master Salt to be used for encrypting transmitted packets
	 * @param rxMasterKey
	 *            Master Key to be used for decrypting received packets
	 * @param rxMasterSalt
	 *            Master Salt to be used for decrypting received packets
	 * @param firstSeqNum
	 *            First sequence number to be used by RTP/SRTP
	 */
	boolean keyExchangeCompleted(byte[] txMasterKey, byte[] txMasterSalt,
			byte[] rxMasterKey, byte[] rxMasterSalt, int firstSeqNum);

	/**
	 * Notify security warning
	 * 
	 * @param securityWarningType
	 *            (ZRTP.SECURITY_WARNING_DOS |
	 *            ZRTP.SECURITY_WARNING_CACHE_MISMATCH)
	 * @param warning
	 *            message describing warning
	 */
	void securityWarning(int securityWarningType, String warning);

	/**
	 * Notification that the session negotiation has been completed.
	 * 
	 * @param uccess
	 *            True if key exchange completed successfully
	 * @param msg
	 *            Message about how session completed, eg errors
	 */
	void sessionNegotiationCompleted(boolean success, String msg);

}
