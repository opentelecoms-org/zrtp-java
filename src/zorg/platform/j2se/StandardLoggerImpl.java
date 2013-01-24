package zorg.platform.j2se;

import java.util.logging.Level;

import zorg.platform.ZrtpLogger;


public class StandardLoggerImpl implements ZrtpLogger {
	
	java.util.logging.Logger logger = java.util.logging.Logger.getLogger("ZRTP");
	String label = ">>> ZRTP <<< ";

	public StandardLoggerImpl(String label) {
		this.label = ">>> ZRTP (" + label + ") <<<";
		logger = java.util.logging.Logger.getLogger("ZRTP (" + label + ")");
	}
	
	public StandardLoggerImpl() {
		
	}

	@Override
	public boolean isEnabled() {
		return true;  // FIXME
	}

	@Override
	public void log(String message) {
		logger.log(Level.INFO, label + message);
	}

	@Override
	public void log(String message, byte[] buffer) {
		logger.log(Level.INFO, label + message + ": " + new UtilsImpl().byteToHexString(buffer));
	}

	@Override
	public void logWarning(String message) {
		logger.warning(label + message);
	}

	@Override
	public void logException(String message) {
		logger.log(Level.SEVERE, label + message);
	}

	@Override
	public void log(String message, byte[] buffer, int offset, int length) {
		// TODO Auto-generated method stub
		
	}

}
