package zorg.platform.j2se;

import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;

import zorg.ZrtpCacheEntry;
import zorg.platform.PersistentHashtable;


public class PersistentHashtableImpl extends HashMap implements
		PersistentHashtable {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	
	public PersistentHashtableImpl() {
		
	}
	
	public void remove(String zid) {
		super.remove(zid);
	}

	public void put(String zid, byte[] data, String phoneNumber) {
		super.put(zid, new ZrtpCacheEntryImpl(data, phoneNumber));
	}

	public Enumeration keys() {
		return Collections.enumeration(keySet());
	}

	public ZrtpCacheEntry get(String zid) {
		return (ZrtpCacheEntry)super.get(zid);
	}

	public void reset() {
		super.clear();
	}


}
