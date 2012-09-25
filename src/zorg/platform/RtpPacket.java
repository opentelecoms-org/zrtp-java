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
 * Generic interface for RTP packets, to get required info for SRTP use
 */
public interface RtpPacket {

	/**
	 * Returns lenght of headers
	 */
	int getHeaderLength();

	/**
	 * Returns packet length
	 */
	int getLength();

	/**
	 * Returns a reference to internal byte arrays, which can be modified by
	 * SRTP
	 */
	byte[] getPacket();

	/**
	 * Returns length of payload only
	 */
	int getPayloadLength();

	/**
	 * Returns sequence number
	 */
	int getSequenceNumber();

	/**
	 * Returns SSCR
	 */
	int getSscr();

	/**
	 * set/update payload length, extending internal array if required
	 */
	void setPayloadLength(int length);

}
