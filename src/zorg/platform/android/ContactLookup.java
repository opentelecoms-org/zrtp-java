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

import android.database.Cursor;
import android.net.Uri;
import android.provider.ContactsContract.PhoneLookup;

public class ContactLookup {

	String name;
	String number;
	Boolean isOnUserAddressBook = false;

	/**
	 * Search for a phone number on the Android AddressBook
	 * 
	 * @param number PhoneNumber
	 */
	public ContactLookup(String number) {
		this.name = number;
		this.number = number;

		if (!number.equals("")) {
			if (number.startsWith("+"))
				number = number.substring(1);
			Cursor c = ((AndroidPlatform) AndroidPlatform.getInstance()).getApplication()
					.getApplicationContext()
					.getContentResolver()
					.query(Uri.withAppendedPath(PhoneLookup.CONTENT_FILTER_URI,
							Uri.encode(number)),
							new String[] { PhoneLookup.DISPLAY_NAME }, null, null,
							null);
			
			if (c.getCount() > 0) {
				isOnUserAddressBook = true;
			}
	
	
			while (c.moveToNext())
				this.name = c.getString(c.getColumnIndexOrThrow(PhoneLookup.DISPLAY_NAME));
			
			c.close();
		}
		
		
	}

	/**
	 * Returns the contact name
	 */
	public String getName() {
		return name;
	}

	/**
	 * Returns the contact phone number
	 */
	public String getNumber() {
		return number;
	}
	
	/**
	 * Returns true if the contact is on the user address book
	 */
	public boolean isOnUserAddressBook() {
		return isOnUserAddressBook;
	}

}
