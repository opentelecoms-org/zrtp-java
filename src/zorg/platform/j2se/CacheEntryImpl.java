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
package zorg.platform.android;

import zorg.ZrtpCacheEntry;

public class AndroidCacheEntry implements ZrtpCacheEntry {

	private static String TEST_VALUE = "E84FE07E054660FFF5CF90B4,null";
	private static String TEST_KEY = "4D795A4944";

	private String zid;
	private byte[] data;
	private String number;

	public AndroidCacheEntry() {
	}

	/**
	 * Create a ZRTP cache entry
	 * @param zid The client ZID
	 * @param data Raw data
	 * @param phoneNumber Client phoneNumber
	 */
	public AndroidCacheEntry(String zid, byte[] data, String phoneNumber) {
		this.zid = zid;
		this.data = data;
		this.number = phoneNumber;
	}

	/* (non-Javadoc)
	 * @see zorg.ZrtpCacheEntry#getData()
	 */
	@Override
	public byte[] getData() {
		return data;
	}

	/**
	 * @return the ZID value
	 * @deprecated
	 */
	@Deprecated
	public String getKey() {
		return zid;
	}

	/* (non-Javadoc)
	 * @see zorg.ZrtpCacheEntry#getNumber()
	 */
	@Override
	public String getNumber() {
		return number;
	}

	/**
	 * Get the ZRTP cache entry string representation, as CSV of an HEX string for the RAW data 
	 * and the phone Number, for example "E84FE07E054660FFF5CF90B4,+3943332233323"
	 * 
	 * @return The string representation 
	 */
	public String getValue() {
		return AndroidPlatform.getInstance().getUtils().byteToHexString(getData()) + "," + getNumber();
	}

	/* (non-Javadoc)
	 * @see zorg.ZrtpCacheEntry#setData(byte[])
	 */
	@Override
	public void setData(byte[] data) {
		this.data = data;
	}

	/* (non-Javadoc)
	 * @see zorg.ZrtpCacheEntry#setNumber(java.lang.String)
	 */
	@Override
	public void setNumber(String number) {
		this.number = number;
	}
	
	/**
	 * Create a Cache Entry, from the Zid string and the CSV representation of HEX RAW data and phone number 
	 * 
	 * @param key ZID string
	 * @param value CSV of HEX raw data and phone number, for example "E84FE07E054660FFF5CF90B4,+3943332233323"
	 * @return a new ZRTP cache entry
	 */
	public static ZrtpCacheEntry fromString(String key, String value) {
		String data = null;
		String number = null;
		int sep = value.indexOf(',');
		if (sep > 0) {
			data = value.substring(0, sep);
			number = value.substring(sep + 1);
		} else {
			data = value;
			number = "";
		}
		byte[] buffer = new byte[data.length() / 2];
		for (int i = 0; i < buffer.length; i++) {
			buffer[i] = (byte) Short.parseShort(
					data.substring(i * 2, i * 2 + 2), 16);
		}
		AndroidCacheEntry entry = new AndroidCacheEntry(key, buffer, number);
		return entry;
	}

	public static void main(String[] args) {
		fromString(TEST_KEY, TEST_VALUE);
	}

}
