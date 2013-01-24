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

/**
 * Contacts lookup utilities
 */
public class AndroidContact {

	private static final int LENGHT_MIN = 8;

	private static boolean fuzzyMatch(String number1, String number2) {
		final String suffix1 = number1.substring(number1.length()
				- AndroidContact.LENGHT_MIN, number1.length());
		final String suffix2 = number2.substring(number2.length()
				- AndroidContact.LENGHT_MIN, number2.length());
		return suffix1.equals(suffix2);
	}

	public static boolean isInternationalFormat(String number) {
		return number.startsWith("+") || number.startsWith("00");
	}

	/**
	 * Get a contact Name from phone number
	 * 
	 * @param aNumber
	 *            Phone number to search for
	 * @return First matching contact name, or the phone number if not found If
	 *         returning a contact name, name will be in the order Prefix, Given
	 *         Name, Family Name (e.g. Mr John Smith)
	 */
	public static AndroidContact lookupByNumber(String aNumber) {
		return new AndroidContact(aNumber);
	}

	/**
	 * Check if two different phone number string are the same phone number
	 * using a fuzzy match alghoritm and an exact string match
	 * 
	 * @param number1
	 * @param number2
	 * @return True if the strings match, False otherwise
	 */
	public static boolean matchingNumbers(String number1, String number2) {
		if (number1 == null || number2 == null) {
			return false;
		}
		if (number1.length() < AndroidContact.LENGHT_MIN
				|| number2.length() < AndroidContact.LENGHT_MIN) {
			return number1.equals(number2);
		}
		if (AndroidContact.isInternationalFormat(number1)
				|| AndroidContact.isInternationalFormat(number2)) {
			return AndroidContact.fuzzyMatch(number1, number2);
		}
		return number1.equals(number2);
	}

	public static AndroidContact normalizeCaller(String caller) {
		AndroidContact c = null;
		int atSign = caller.indexOf('@');
		if (atSign != -1) {
			c = AndroidContact.lookupByNumber(caller.substring(0, atSign));
		} else {
			c = AndroidContact.lookupByNumber(caller);
		}
		return c;
	}

	private final String name;

	private final String number;
	
	private final boolean isOnUserAddressBook;

	private AndroidContact(String number) {
		final ContactLookup i = new ContactLookup(number);
		name = i.getName();
		this.number = i.getNumber();
		this.isOnUserAddressBook = i.isOnUserAddressBook();
	}

	/**
	 * @return contact name if present or number if contact was not found in
	 *         addressbook
	 */
	public String getContact() {
		return name != null ? name : number;
	}

	/**
	 * @return contact name if found or null if lookup failed
	 */
	public String getName() {
		return name;
	}

	/**
	 * @return contact formatted number
	 */
	public String getNumber() {
		return number;
	}
	
	public boolean isOnUserAddressBook() {
		return isOnUserAddressBook;
	}

}
