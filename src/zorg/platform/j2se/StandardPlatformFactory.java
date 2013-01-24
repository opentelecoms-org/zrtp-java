package zorg.platform.j2se;

import zorg.platform.PlatformFactory;
import zorg.platform.ZrtpLogger;

public class StandardPlatformFactory implements PlatformFactory {

	@Override
	public boolean getDebugFlag() {
		// J2SE platform support is not yet complete, so Debug = true
		// FIXME: change this when persistent storage and contact
		// lookup implemented in some useful manner, otherwise, 
		// J2SE support is only for testing
		return true;
	}

	@Override
	public ZrtpLogger getLogger() {
		return new StandardLoggerImpl();
	}

}
