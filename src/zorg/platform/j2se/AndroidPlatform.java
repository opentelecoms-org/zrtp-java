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

import android.app.Application;
import zorg.TestSettings;
import zorg.platform.AddressBook;
import zorg.platform.CryptoUtils;
import zorg.platform.PersistentHashtable;
import zorg.platform.Platform;
import zorg.platform.PlatformFactory;
import zorg.platform.RandomGenerator;
import zorg.platform.Utils;
import zorg.platform.ZrtpLogger;

public class AndroidPlatform implements Platform {

	private Utils utils ;
	private ZrtpLogger logger;
	private ZrtpCacheDB storage;
	private CryptoUtils cryptoUtils;
	private AddressBook addressbook;
	private final RandomGenerator rg;
	private static Platform instance;

	private Application applicationInstance; 
	
	private boolean isDebugBuild;
	
	private AndroidPlatform (PlatformFactory androidFactory,  Application applicationInstance) {
		this.applicationInstance = applicationInstance;
		
		logger = androidFactory.getLogger();
		addressbook = new AndroidAddressBookAdaptor();
		utils = new AndroidUtils();
		storage = new ZrtpCacheDB(applicationInstance, androidFactory.getLogger());
		cryptoUtils = new AndroidCryptoUtils();
		
		rg 		= AndroidRandomGenerator.getInstance();
		cryptoUtils.setRandomGenerator(rg);

		isDebugBuild = androidFactory.getDebugFlag();		
	}
	
	/**
	 * Init the Android ZRTP Platform
	 * 
	 * @param androidFactory an Android Platform implementation
	 * @param applicationInstance the android.app.Application instance
	 */
	public static void init(PlatformFactory androidFactory, Application applicationInstance) {
		instance = new AndroidPlatform(androidFactory, applicationInstance);
	}
	
	public static Platform getInstance() {
		return instance;
	}

	@Override
	public AddressBook getAddressBook() {
		return addressbook;
	}

	@Override
	public CryptoUtils getCrypto() {
		return cryptoUtils;
	}

	@Override
	public PersistentHashtable getHashtable() {
		return storage;
	}

	@Override
	public ZrtpLogger getLogger() {
		return logger;
	}

	@Override
	public Utils getUtils() {
		return utils;
	}

	public boolean isDebugVersion() {
		return isDebugBuild;
	}

	@Override
	public boolean isVerboseLogging() {
		return isDebugBuild && TestSettings.ZRTP_VERBOSE_LOGGING;
	}

	@Override
	public RandomGenerator getRandomGenerator() {
		return rg;
	}
	
	/**
	 * @return The android.app.Application instance
	 */
	public Application getApplication() {
		return applicationInstance;
	}
}
