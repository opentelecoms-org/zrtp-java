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

import zorg.TestSettings;
import zorg.platform.AddressBook;
import zorg.platform.CryptoUtils;
import zorg.platform.PersistentHashtable;
import zorg.platform.Platform;
import zorg.platform.PlatformFactory;
import zorg.platform.RandomGenerator;
import zorg.platform.Utils;
import zorg.platform.ZrtpLogger;

public class BBPlatform implements Platform {

	private static Platform instance;
	private final ZrtpLogger logger;
	private final AddressBook ab;
	private final BBCryptoUtils cu;
	private final BBByteUtils bu;
	private final RandomGenerator rg;
	private PlatformFactory bbfactory;
	
	private boolean isDebugBuild;
	
	private BBPlatform(PlatformFactory bbfactory) {

		this.bbfactory = bbfactory; 
		
		logger = bbfactory.getLogger();
		ab     = new BBAddressBook();
		cu     = new BBCryptoUtils();
		bu     = new BBByteUtils(); 
		rg     = BBRandomGenerator.getInstance();
		
		cu.setRandomGenerator(rg);
		isDebugBuild = bbfactory.getDebugFlag();
	}
	
	public static void init(PlatformFactory bbfactory) {
		instance = new BBPlatform(bbfactory);
	}
	
	public static Platform getPlatform() {
		return instance;
	}
	
	public ZrtpLogger getLogger() {
		return logger;
	}
	
	public AddressBook getAddressBook() {
		return ab;
	}

	public boolean isVerboseLogging() {
	    return isDebugBuild && TestSettings.ZRTP_VERBOSE_LOGGING;
    }

	public Utils getUtils() {
	    return bu;
    }

	public CryptoUtils getCrypto() {
	    return cu;
    }

	public PersistentHashtable getHashtable() {
		HashtableAdapter ht = new HashtableAdapter(bbfactory.getLogger());
	    return ht;
    }

	public RandomGenerator getRandomGenerator() {
		return rg;
	}
}
