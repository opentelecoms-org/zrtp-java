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

import java.util.Enumeration;

import zorg.platform.PersistentHashtable;
import zorg.platform.Platform;

/**
 * ZRTP cache stores this client's ZID and shared secrets indexed by the remote
 * ZID.
 */
public class ZRTPCache {

	public static final String LOCAL_ZID_KEY = "MyZID"; // should not be 8 bytes ong

	PersistentHashtable cache;
	String currentZid;
	byte[] currentRs1;
	byte[] currentRs2;
	boolean currentTrust;
	String currentNumber; // Phone number of other party
	private boolean UPDATE_FOR_CACHE_MISMATCH_SIMULATION = false;
	private final Platform platform;

	ZRTPCache(Platform platform) {
		this.platform = platform;
		UPDATE_FOR_CACHE_MISMATCH_SIMULATION = TestSettings.TEST_ZRTP_CACHE_MISMATCH;
		/*
		 * Implementation info: Each entry contains the expiration timestamp (8
		 * bytes, little endian, in ms as system time), trust (1 byte, 0 or 1),
		 * rs1 (32 bytes) and optionally rs2 (32 bytes).
		 */
		cache = platform.getHashtable();
	}

	public String getCurrentNumber() {
		return currentNumber;
	}

	/**
	 * Retrieves this clients cached ZID. If there's no cached ZID, i.e. on
	 * first run, a random ZID is created and stored.
	 * 
	 * @return this client's ZID.
	 */
	public byte[] getMyZid() {
		ZrtpCacheEntry ce = cache.get(LOCAL_ZID_KEY);
		if (ce != null) {
			return ce.getData();
		} else {
			byte[] zid = new byte[12];
			platform.getCrypto().getRandomGenerator().getBytes(zid);
			cache.put(LOCAL_ZID_KEY, zid, null);
			platform.getLogger().log("[ZRTP] created new ZID=", zid);
			return zid;
		}
	}

	public byte[] getRetainedSecret1() {
		return currentRs1;
	}

	public byte[] getRetainedSecret2() {
		return currentRs2;
	}

	public boolean getTrust() {
		return currentTrust;
	}

	public boolean isNewZidForTrustedUser(String aNumber) {
		boolean wasTrusted = false;
		for (Enumeration e = cache.keys(); e.hasMoreElements();) {
			String key = (String) e.nextElement();
			ZrtpCacheEntry ce = cache.get(key);
			if (ce.getNumber() != null) {
				if (platform.getAddressBook().matchingNumbers(ce.getNumber(),
						aNumber)) {
					byte[] data = ce.getData();
					if (data[8] == 1) {
						wasTrusted = true;
					}
					cache.remove(key);
					break;
				}
			}
		}
		return wasTrusted;
	}

	/**
	 * Selects a cache entry base on remote ZID
	 * 
	 * @param remoteZID
	 *            the remote ZID of the requested entry.
	 */
	public void selectEntry(byte[] remoteZID) {
		platform.getLogger().log(
				"ZRTPCache: selectEntry("
						+ platform.getUtils().byteToHexString(remoteZID) + ")");
		String zidString = new String(remoteZID);
		if (currentZid != null && currentZid.equals(zidString)) {
			return;
		}
		currentZid = null;
		currentRs1 = null;
		currentRs2 = null;
		currentTrust = false;
		currentNumber = null;
		ZrtpCacheEntry ce = cache.get(zidString);
		if (ce == null) {
			currentZid = zidString;
			return;
		}
		byte[] data = ce.getData();
		if (data.length == 40 || data.length == 72) {
			// backward compatibility: insert trust flag = false
			byte[] newData = new byte[1 + data.length];
			newData[0] = 0;
			System.arraycopy(data, 0, newData, 1, data.length);
			data = newData;
		}
		if (data.length != 41 && data.length != 73) {
			platform.getLogger()
					.logWarning("Invalid shared secret cache entry");
			currentZid = zidString;
			return;
		}
		long expiry = 0;
		for (int i = 8; i != 0;) {
			expiry = (expiry << 8) + (data[--i] & 0xffL);
		}
		long now = System.currentTimeMillis();
		if (expiry > now) {
			currentTrust = (data[8] != 0);
			currentRs1 = new byte[32];
			System.arraycopy(data, 9, currentRs1, 0, 32);
			if (data.length == 73) {
				currentRs2 = new byte[32];
				System.arraycopy(data, 41, currentRs2, 0, 32);
			}
		}

		currentNumber = ce.getNumber();
		currentZid = zidString;
		// //// TEST
		if (UPDATE_FOR_CACHE_MISMATCH_SIMULATION) {
			if (currentRs1 != null)
				currentRs1 = platform.getCrypto().getRandomGenerator()
						.getBytes(currentRs1.length);
			if (currentRs2 != null)
				currentRs2 = platform.getCrypto().getRandomGenerator()
						.getBytes(currentRs2.length);
			if (currentRs1 != null || currentRs2 != null) {
				updateEntry(expiry, currentTrust, currentRs1, currentRs2,
						currentNumber);
			}
			UPDATE_FOR_CACHE_MISMATCH_SIMULATION = false;
		}
		// //// TEST
		currentTrust &= (platform.getAddressBook()
				.isInAddressBook(currentNumber));

	}

	/**
	 * Updates the entry for the selected remote ZID.
	 * 
	 * @param retainedSecret
	 *            the new retained secret.
	 * @param expiryTime
	 *            the expiry time, 0 means the entry should be erased.
	 * @param keepRs2
	 *            specifies whether the old rs2 should be kept rather than
	 *            copying old rs1 into rs2.
	 * @param number
	 *            Phone Number associated with the current zid
	 */
	public void updateEntry(long expiryTime, boolean trust,
			byte[] retainedSecret, byte[] rs2, String number) {
		if (platform.isVerboseLogging()) {
			platform.getLogger().log(
					"ZRTPCache: updateEntry("
							+ expiryTime
							+ ", "
							+ trust
							+ ", "
							+ platform.getUtils().byteToHexString(
									retainedSecret) + ", "
							+ platform.getUtils().byteToHexString(rs2) + ","
							+ number + ")");
		}
		if (expiryTime == 0) {
			cache.remove(currentZid);
			currentTrust = false;
			currentRs1 = null;
			currentRs2 = null;
			currentNumber = null;
		} else {
			byte[] data = new byte[(rs2 == null) ? 41 : 73];
			for (int i = 0; i != 8; ++i) {
				data[i] = (byte) (expiryTime & 0xff);
				expiryTime >>>= 8;
			}
			data[8] = (byte) (trust ? 1 : 0);
			System.arraycopy(retainedSecret, 0, data, 9, 32);
			if (rs2 != null) {
				System.arraycopy(rs2, 0, data, 41, 32);
			}
			cache.put(currentZid, data, number);
			currentTrust = trust;
			currentRs1 = retainedSecret;
			currentRs2 = rs2;
			currentNumber = number;
		}
	}

	public void updateNumber(long expiryTime, String phoneNumber) {
		currentNumber = phoneNumber;
		ZrtpCacheEntry ce = cache.get(currentZid);
		cache.put(currentZid, ce.getData(), currentNumber);
	}

	/* if receive a remoteTrust == false, reset current cache status */
	public void resetTrust(byte[] farEndZID) {
		platform.getLogger().log("ZRTPCache: resetTrust(", farEndZID);
		
		String zidString = new String(farEndZID);
		ZrtpCacheEntry ce = cache.get(zidString);
		if (ce == null) return;
		
		byte[] data = ce.getData();
		data[8] = (byte) 0;
		cache.put(zidString, data, ce.getNumber());
		
		if (currentZid.equals(zidString))
			currentTrust = false; 
	}

}