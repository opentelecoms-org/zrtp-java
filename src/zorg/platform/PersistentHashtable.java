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

import java.util.Enumeration;

import zorg.ZrtpCacheEntry;

/**
 * Adapter interface for a persistent map. Every change operation is
 * automatically persisted
 * */
public interface PersistentHashtable {

	/**
	 * find a cache entry for specified ZID
	 * 
	 * @param key
	 * @return cache entry
	 */
	ZrtpCacheEntry get(String zid);

	/**
	 * Returns enumeration of all ZIDs
	 * 
	 * @return
	 */
	Enumeration keys();

	/**
	 * Add/replace a cache entry for specified ZID
	 * 
	 * @param zid
	 *            ZID index
	 * @param data
	 *            binary data bound to ZID
	 * @param phoneNumber
	 *            phone number bound to ZID
	 */
	void put(String zid, byte[] data, String phoneNumber);

	/**
	 * Remove cache entry for specified ZID
	 * 
	 * @param zid
	 */
	void remove(String zid);

	/**
	 * Reset cache and remove from persistent storage
	 */
	void reset();
	
}
