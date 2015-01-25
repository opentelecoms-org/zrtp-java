package zorg;

import java.security.Security;
import java.util.LinkedList;
import java.util.Queue;
import java.util.logging.Logger;


import org.bouncycastle.jce.provider.BouncyCastleProvider;
import zorg.platform.Platform;
import zorg.platform.RtpStack;
import zorg.platform.ZrtpListener;

/*
 * Test harness for the ZRTP implementation
 * 
 * Packets are `transmitted' between two ZRTP agents using a queue
 * Sleeps are used to simulate network latency
 * The queue is also used as a mechanism to avoid recursion between the
 * two agents (a.handleMessage(b.handleMessage(a.handleMessage))) scenario
 * 
 * TODO:
 * - check the result
 * - stop all the threads at completion
 * 
 */
public class TestHarness {
	
	// delay value in ms
	public final static int SIMULATE_NETWORK_DELAY = 50;
	
	Logger logger = Logger.getLogger(getClass().getName());
	
	static Queue<ZrtpPacket> queue;
	
	ZRTP zrtp;
	String label;
	
	TestHarness(String label) {
		this.label = label;
		//Platform platform = AndroidPlatform.getInstance();
		Platform platform = new zorg.platform.j2se.PlatformImpl();
		zrtp = new ZRTP(platform);
		zrtp.setPhoneNumber(label);   // FIXME - make this configurable?
		zrtp.setProtocolManager(new ZRTPListener());
		zrtp.setRtpStack(new TestRtpStack());
	}
	
	void start() {
		zrtp.startSession();
	}
	
	class ZRTPListener implements ZrtpListener {

		@Override
		public void sessionNegotiationCompleted(boolean success, String msg) {
				logger.info("*********** Got callback from ZRTP: " + success
						+ ", " + msg);
				logger.info("*********** Got SaS from ZRTP: "
						+ zrtp.getSasString());
			
		}

		@Override
		public void securityWarning(int securityWarningType, String warning) {
			
			logger.info("*********** Got warning from ZRTP: "
						+ securityWarningType + ", " + warning);
		}

		@Override
		public boolean keyExchangeCompleted(byte[] txMasterKey,
				byte[] txMasterSalt, byte[] rxMasterKey, byte[] rxMasterSalt,
				int firstSeqNum) {
			logger.info("*********** Got master keys from ZRTP!!!  *******************");
			return true;
		}
	}
	
	class TestRtpStack implements RtpStack {

		@Override
		public void sendZrtpPacket(byte[] data) {
			// TODO Auto-generated method stub
			ZrtpPacket pkt = new ZrtpPacket(data, label);
			sendPacket(pkt);
			
		}

		@Override
		public void setNextZrtpSequenceNumber(int startSeqNum) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void setMasqueradingDual() {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void setMasqueradingActive() {
			// TODO Auto-generated method stub
			
		}
		
	}
	
	class ZrtpPacket {
		byte[] data;
		String src;
		public ZrtpPacket(byte[] data, String src) {
			this.data = data;
			this.src = src;
		}
		public byte[] getData() {
			return data;
		}
		public String getSrc() {
			return src;
		}
	}
	
	void sendPacket(ZrtpPacket pkt) {
		synchronized(queue) {
			queue.add(pkt);
			queue.notifyAll();
		}
		try {
			Thread.sleep(10);
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	void handlePacket(ZrtpPacket pkt) {
		byte[] data = pkt.getData();
		zrtp.handleIncomingMessage(data, 0, data.length);
	}
	  
    public static void main(String[] args) {
    	Logger _logger = Logger.getLogger(TestHarness.class.getName());
    	_logger.info("Beginning ZRTP test case");
    	
    	Security.insertProviderAt(new BouncyCastleProvider(), 1);
    	
    	queue = new LinkedList<ZrtpPacket>();
    	
    	TestHarness th1 = new TestHarness("A");
    	TestHarness th2 = new TestHarness("B");
    	
    	_logger.info("Starting tests...");
    	
    	th1.start();
    	th2.start();
    	
    	_logger.info("Tests started");
    	
    	while(true) {
    		ZrtpPacket pkt = null;
    	
    		synchronized(queue) {
    			while(pkt == null) {
    				try {
    					if(queue.isEmpty())
    						queue.wait();
    				} catch (InterruptedException e) {
    					_logger.info("Interrupted!");
    				}
    				pkt = queue.poll();
    			}
    		}
    		
    		if(pkt.getSrc().equals("A"))
    			th2.handlePacket(pkt);
    		else if(pkt.getSrc().equals("B"))
    			th1.handlePacket(pkt);
    		else
    			throw new RuntimeException("Unknown source!");
    		
    		try {
				Thread.sleep(SIMULATE_NETWORK_DELAY);
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
    		
    		pkt = null;
    	}
    	
    	
    }
}
