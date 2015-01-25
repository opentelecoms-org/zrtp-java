package zorg.platform.j2se;

import zorg.platform.AddressBook;

public class AddressBookImpl implements AddressBook {

	public boolean matchingNumbers(String number1, String number2) {
		// FIXME - use libphonenumber
		return number1.equals(number2);
	}

	public boolean isInAddressBook(String phoneNumber) {
		// FIXME - not a real address book
		return false; 
	}

}
