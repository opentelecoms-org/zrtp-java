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
package zorg.platform.blackberry;

import net.rim.blackberry.api.phone.phonelogs.PhoneCallLogID;


/**
 * Contacts lookup utilities
 */
public class BBContact {

	private String number;
	private String name;
	
	/**
	 * @return contact formatted number
	 */
	public String getNumber() {
    	return number;
    }

	/**
	 * @return contact name if found or null if lookup failed
	 */
	public String getName() {
    	return name;
    }
	
	/**
	 * @return contact name if present or number if contact was not found in addressbook
	 */
	public String getContact() {
		return name != null
		     ? name
		     : number;
	}
	
	private BBContact(String number) {
        PhoneCallLogID pci = new PhoneCallLogID(number);
        this.name = pci.getName();
        try {
        	this.number = pci.getAddressBookFormattedNumber();
        } catch (Exception e) {
			// Device is locked or contact list is protected
        	this.number = number;
		}
	}
	
    /**
     * Get a contact Name from phone number
     * @param aNumber Phone number to search for
     * @return First matching contact name, or the phone number if not found
     *         If returning a contact name, name will be in the order Prefix, Given Name, Family Name
     *         (e.g. Mr John Smith)
     */
    public static BBContact lookupByNumber(String aNumber) {         
        return new BBContact(aNumber);
    }
    
	private static final int LENGHT_MIN = 8;
	
    public static boolean matchingNumbers(String number1, String number2) {
    	if(number1 == null || number2 == null) return false;
    	if(number1.length() < LENGHT_MIN || number2.length() < LENGHT_MIN) return number1.equals(number2); 
    	if(isInternationalFormat(number1) || isInternationalFormat(number2)) return fuzzyMatch(number1, number2);
    	return number1.equals(number2);
    }

	private static boolean fuzzyMatch(String number1, String number2) {
	    String suffix1 = number1.substring(number1.length()-LENGHT_MIN, number1.length());
    	String suffix2 = number2.substring(number2.length()-LENGHT_MIN, number2.length());
    	return suffix1.equals(suffix2);
    }

    public static boolean isInternationalFormat(String number) {
    	return number.startsWith("+") || number.startsWith("00");
    }
 
 /*   
	private static void test() {
		assertFalse(matchingNumbers("", null));
		assertFalse(matchingNumbers(null, null));
		assertTrue(matchingNumbers("", ""));
		assertFalse(matchingNumbers("111", "2222"));
		
		assertTrue(matchingNumbers("333", "333"));
		assertFalse(matchingNumbers("3334", "333"));
		assertFalse(matchingNumbers("3334", "4333"));
		
		assertTrue(matchingNumbers("12345678", "12345678"));
		assertFalse(matchingNumbers("512345678", "412345678"));
		assertTrue(matchingNumbers("+3912345678", "+3912345678"));
		assertTrue(matchingNumbers("+3912345678", "12345678"));
		assertTrue(matchingNumbers("003912345678", "+3912345678"));
		assertTrue(matchingNumbers("003912345678", "12345678"));
		
	}

	private static void assertTrue(boolean matchingNumbers) {
	    Logger.log(matchingNumbers ? "OK" : "KO");
    }

	private static void assertFalse(boolean matchingNumbers) {
		assertTrue(!matchingNumbers);
    }*/

} 
