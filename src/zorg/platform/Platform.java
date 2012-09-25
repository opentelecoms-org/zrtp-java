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
 * Factory for platform specific implementation
 */
public interface Platform {

	/**
	 * Returns the native phone Addressbook
	 */
	AddressBook getAddressBook();

	/**
	 * Returns platform specific CryptoUtils
	 * 
	 * @return
	 */
	CryptoUtils getCrypto();

	/** returns reference to persistent cache used by ZRTP */
	PersistentHashtable getHashtable();

	/**
	 * Returns a logger object for debugging purposes
	 */
	ZrtpLogger getLogger();

	/**
	 * Returns platform specific utils
	 */
	Utils getUtils();

	/**
	 * Returns if ZRTP is running in debug mode
	 * 
	 * @return
	 */
	boolean isVerboseLogging();
	

	/**
	 * Returns the RandomGenerator instance
	 * 
	 * @return
	 */
	RandomGenerator getRandomGenerator();
}
