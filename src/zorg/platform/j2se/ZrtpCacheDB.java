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
package zorg.platform.j2se;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.Vector;

import zorg.ZrtpCacheEntry;
import zorg.platform.PersistentHashtable;
import zorg.platform.ZrtpLogger;

public class ZrtpCacheDB implements PersistentHashtable {
	
	private ZrtpLogger logger;
	Map<String,ZrtpCacheEntry> store = new HashMap<String,ZrtpCacheEntry>(); 
	
	public ZrtpCacheDB(ZrtpLogger l) {
		logger = l;
	}

	@Override
	public ZrtpCacheEntry get(String zid) {
		ZrtpCacheEntry entry = null;

		entry = store.get(zid);
		
		if (entry != null) {
			logger.log("[Zrtp Cache] Entry for "  + zid + " and number " + entry.getNumber() + " found!");
		} else
			logger.log("[Zrtp Cache] No entry found!");
		
		return entry;
	}

	@Override
	public Enumeration<String> keys() {
		Set<String> keys = store.keySet();		
		logger.log("[Zrtp Cache] Found " + keys.size() + " keys in zrtp_cache_db");
		return new Vector<String>(keys).elements();
	}

	@Override
	public void put(String zid, byte[] data, String phoneNumber) {
		/* first, search for a data to update */
		ZrtpCacheEntry oldEntry = get(zid);
		
		if (oldEntry != null) {
			logger.log("[Zrtp Cache] An old data found...update it!");
			/* UPDATE DATA */

			oldEntry.setData(data);
			oldEntry.setNumber(phoneNumber);
		} else {
			logger.log("[Zrtp Cache] Insert new data!");
			/* INSERT DATA */
			ZrtpCacheEntry entry = new CacheEntryImpl();
			entry.setData(data);
			entry.setNumber(phoneNumber);

			store.put(zid, entry);
		}
		
	}

	@Override
	public void remove(String zid) {
		store.remove(zid);
		logger.log("[Zrtp Cache] deleted element for zid " + zid);
	}

	@Override
	public void reset() {
		store.clear();
		logger.log("[Zrtp Cache] Reset zrtp_cache_db");
	}
	
}
