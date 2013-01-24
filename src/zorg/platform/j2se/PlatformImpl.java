package zorg.platform.j2se;

import zorg.platform.AddressBook;
import zorg.platform.CryptoUtils;
import zorg.platform.PersistentHashtable;
import zorg.platform.RandomGenerator;
import zorg.platform.Utils;
import zorg.platform.ZrtpLogger;

public class PlatformImpl implements zorg.platform.Platform {
	
	ZrtpLogger logger = new StandardLoggerImpl();
	Utils utils = new UtilsImpl();
	CryptoUtils cryptoUtils = new CryptoUtilsImpl();
	PersistentHashtable ht = new PersistentHashtableImpl();
	AddressBook addresses = new AddressBookImpl();
	String label;
	
	public PlatformImpl() {
		this.label = "";
	}

	public PlatformImpl(String label) {
		this.label = label;
		logger = new StandardLoggerImpl(label);
	}

	@Override
	public ZrtpLogger getLogger() {
		return logger;
	}

	@Override
	public AddressBook getAddressBook() {
		return addresses;
	}

	@Override
	public CryptoUtils getCrypto() {
		return cryptoUtils;
	}

	@Override
	public Utils getUtils() {
		return utils;
	}

	@Override
	public PersistentHashtable getHashtable() {
		return ht;
	}

	@Override
	public boolean isVerboseLogging() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public RandomGenerator getRandomGenerator() {
		// TODO Auto-generated method stub
		return null;
	}

}
