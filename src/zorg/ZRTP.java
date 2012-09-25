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
package zorg;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Timer;
import java.util.TimerTask;

import zorg.platform.DiffieHellmanSuite;
import zorg.platform.Digest;
import zorg.platform.Platform;
import zorg.platform.RandomGenerator;
import zorg.platform.RtpStack;
import zorg.platform.ZrtpListener;

/**
 * Handles ZRTP protocol and key generation/exchange
 */
public class ZRTP {
	

    // Session hash values to be calculated at start of session
	class HashChain {
		byte[] H0;
		byte[] H1;
		byte[] H2;
		byte[] H3;
		boolean helloHashCreated;

		public HashChain() {
			// Creates the initial hash chain used in hello messages
			H0 = new byte[32];
			randomGenerator.getBytes(H0);
			H1 = new byte[32];
			H2 = new byte[32];
			H3 = new byte[32];

			// Generate the hash chain (draft-zimmermann-avt-zrtp-17, Section 9)
			// Use implicit Hash (SHA-256)
			Digest digest = platform.getCrypto().createDigestSHA256();
			digest.update(H0, 0, H0.length);
			digest.getDigest(H1, 0, true);
			digest.update(H1, 0, H1.length);
			digest.getDigest(H2, 0, true);
			digest.update(H2, 0, H2.length);
			digest.getDigest(H3, 0, true);
		}

		public void clear() {
			H0 = null;
			H1 = null;
			H2 = null;
			H3 = null;
		}
	}

	/**
	 * Timer task to be used on expiry of hello timer
	 */
	protected class RetranTimerTask extends TimerTask {
		public void run() {
			retranTimerExpired(this);
		}
	}

	/*
	 * Flag whether to use s1 instead of rs1 as the new rs2 when updating the
	 * shared secret cache. This deviation from the ZRTP spec, section 4.6.1.,
	 * prevents a rare situation when two missed updates on one client will push
	 * the other client out of sync and cause a cache mismatch. At first look,
	 * this should not compromise security but a deeper analysis was not
	 * performed.
	 */
	private static final boolean ZRTP_461_FIX_TO_USE_S1_INSTEAD_OF_RS1 = false;

	// 4 bytes version field
	public final static String VERSION = "1.10";
	// Relevant part of version field, used for version negotiation
	public final static String VERSION_PREFIX = VERSION.substring(0, 3);

	public static final String CLIENT_ID_LEGACY = "KhamsaPrivateGSM";
	public static final String CLIENT_ID_RFC    = "PWaveIPrivateGSM";
	
	public final static int SECURITY_WARNING_DOS = 1;
	public final static int SECURITY_WARNING_CACHE_MISMATCH = 2;
	
	// ZRTP States
	private final static int ZRTP_STATE_INACTIVE      = 0;
	private final static int ZRTP_STATE_SENDING_HELLO = 1;
	private final static int ZRTP_STATE_GOT_HELLO_ACK = 2;
	private final static int ZRTP_STATE_GOT_COMMIT    = 3;
	private final static int ZRTP_STATE_COMMIT_SENT   = 4;
	private final static int ZRTP_STATE_GOT_DHPART1   = 5;
	private final static int ZRTP_STATE_DHPART1_SENT  = 6;
	private final static int ZRTP_STATE_GOT_DHPART2   = 7;
	private final static int ZRTP_STATE_DHPART2_SENT  = 8;
	private final static int ZRTP_STATE_GOT_CONFIRM1  = 9;
	private final static int ZRTP_STATE_CONFIRM1_SENT = 10;
	private final static int ZRTP_STATE_GOT_CONFIRM2  = 11;
	private final static int ZRTP_STATE_CONFIRM2_SENT = 12;
	private final static int ZRTP_STATE_GOT_CONF2ACK  = 13;
	private final static int ZRTP_STATE_CONF2ACK_SENT = 14;
	
	// Timeouts & Retransmissions
	private final static int T1_INITIAL_INTERVAL    = 50;
	private final static int T1_MAXIMUM_INTERVAL    = 200;
	private final static int T1_MAX_RETRANSMISSIONS = 200;
	private final static int T2_INITIAL_INTERVAL    = 150;
	private final static int T2_MAXIMUM_INTERVAL    = 1200;
	private final static int T2_MAX_RETRANSMISSIONS = 10;

	// The optional responder timeout between Commit and Confirm2, see ZRTP
	// spec, section 6
	private final static int RESPONDER_TIMEOUT = 40000; // 20s (more than the
														// suggested 10s)
	
	// Protocol error codes
	private final static int ZRTP_ERROR_MALFORMED_PACKET          = 0x10;
	private final static int ZRTP_ERROR_CRITICAL_SW_FAULT         = 0x20;
	private final static int ZRTP_ERROR_INCORRECT_VERSION         = 0x30;
	private final static int ZRTP_ERROR_HELLO_MISMATCH            = 0x40;
	private final static int ZRTP_ERROR_UNSUPPORTED_HASH          = 0x51;
	private final static int ZRTP_ERROR_UNSUPPORTED_CIPHER        = 0x52;
	private final static int ZRTP_ERROR_UNSUPPORTED_KEY_EXCHANGE  = 0x53;
	private final static int ZRTP_ERROR_UNSUPPORTED_SRTP_AUTH     = 0x54;
	private final static int ZRTP_ERROR_UNSUPPORTED_SAS_SCHEME    = 0x55;
	private final static int ZRTP_ERROR_UNAVAILABLE_SHARED_SECRET = 0x56;
	private final static int ZRTP_ERROR_DH_BAD_PVI                = 0x61;
	private final static int ZRTP_ERROR_DH_HVI_WRONG              = 0x62;
	private final static int ZRTP_ERROR_UNTRUSTED_SAS             = 0x63;
	private final static int ZRTP_ERROR_BAD_CONFIRM_HMAC          = 0x70;
	private final static int ZRTP_ERROR_NONCE_REUSED              = 0x80;
	private final static int ZRTP_ERROR_EQUAL_ZIDS_IN_HELLO       = 0x90;
	private final static int ZRTP_ERROR_SERVICE_UNAVAILABLE       = 0xA0;
	private final static int ZRTP_ERROR_PROTOCOL_TIMEOUT          = 0xB0;
	private final static int ZRTP_ERROR_UNALLOWED_GO_CLEAR_RCVD   = 0x100;
	
	// Current implementation support only one ECDH suite, EC25 or EC38. Default is EC38
	private boolean DH_MODE_EC_USE_256 = TestSettings.KEY_TYPE_EC25;

	private ZrtpListener listener = null;
	private RtpStack rtpStack = null;
	private int state = ZRTP_STATE_INACTIVE;
	private boolean started = false;
	private int seqNum;
	private boolean completed; // Set to true when zrtp session is completed
	
	private byte[] txMasterKey;  // Byte array for generated TX Master Key
	private byte[] txMasterSalt; // Byte array for generated TX Master Salt
	private byte[] rxMasterKey;  // Byte array for generated RX Master Key
	private byte[] rxMasterSalt; // Byte array for generated RX Master Salt
	
	private Timer retranTimer;          // Retransmission timer
	private RetranTimerTask retranTask; // Timer task used by Retran timer
	private int timerInterval;          // Current retran timer interval in milliseconds
	private int retranCount;            // Number of retransmissions so far
	private long lastPacketArrival;     // last ZRTP packet arrival, for responder
									    // timeout
	
	private boolean initiator;     // True if acting as the zrtp initiator
	private byte[] localZID;       // ZRTP Identifier
	private String farEndClientID; // ClientId of other end
	private byte[] farEndZID;      // ZRTP Identifier of other end
	private byte[] farEndH0;       // H0 in hash chain of far end (as indicated in Confirm)
	// private byte[] farEndH1; // H1 in hash chain of far end (as indicated in DHPart1 or 2)
	// private byte[] farEndH2; // H2 in hash chain of far end (as indicated in Commit)
	// private byte[] farEndH3; // H3 in hash chain of far end (as indicated  Hello)
	
	private KeyAgreementType dhMode; // Indicates which Diffie-Hellman mode in use
	private CipherType cipherInUse; // Indicates which cipher is in use
	private SasType sasMode;   // Indicates which SAS mode is in use
	private HashType hashMode; // Indicates which Hash type is in use
	
	private byte[] dhPart1Msg; // Saved DHPart1 Message (needed in shared secret calculation)
	private byte[] dhPart2Msg; // Saved DHPart2 Message (needed in shared secret calculation)
	private byte[] rxHelloMsg; // Received Hello Message, saved for use in creating Commit message
	private byte[] txHelloMsg; // Transmitted Hello Message, saved for possible use in key generation
	private byte[] txPingMsg;  // Transmitted Ping Message
	private byte[] commitMsg;  // Saved Commit message (needed in shared secret calculation)
	private String sasString;  // Holds the SAS after it has been calculated
	private String phoneNumber; // Used for addressbook lookup during verification
	
	// private boolean forceToBeInitiator = false;
	private boolean forceToBeResponder = false;
	// ZRTP shared secret cache handling
	private ZRTPCache cache;
	private boolean delayedCacheUpdate; // delayed update because of shared secret cache mismatch
	private boolean remoteTrust;
	private long confirm1Timestamp;
	private long cacheExpiry; // should be unsigned but Java doesn't support unsigned types!
	
	// the other party is NOT RFC-compliant client
	private boolean isLegacyClient;

	byte[] newRS;
	byte[] keepRS2;
	// Security warning flags: 1 = DoS, 2 = cache mismatch
	private int securityWarningFlags;
	// Accurately saved sent and received messages needed for shared secret
	// calculation
	private byte[] msgCommitTX;
	private byte[] msgCommitRX;
	private byte[] msgDhPart1TX;
	private byte[] msgDhPart1RX;
	private byte[] msgDhPart2TX;
	private byte[] msgDhPart2RX;
	private byte[] msgConfirm1TX;
	private byte[] msgConfirm1RX;
	private byte[] msgConfirm2TX;
	private byte[] msgConfirm2RX;
	private byte[] msgErrorTX;

	private HashChain hashChain;
	
	// Shared secrets
	private byte[] s0; // Byte array for s0 in zrtp spec
	private byte[] s1; // "     " "  s1 " "    "
	private byte[] s2; // "     " "  s2 " "    "
	private byte[] s3; // "     " "  s3 " "    "
	private byte[] dhResult;
	private byte[] kdfContext; // KDF Context used in key generation, zrtp spec, 4.4.1.4
	private byte[] totalHash; // Total Hash used in key generation, zrtp spec, 4.4.1.4
	
	// Optional: Hash of the Hello message to be received. This hash is sent by
	// the other
	// end as part of the SDP for further verification. If not received we wont
	// check the Hello message
	private String sdpHelloHashReceived = null;
	// Hello hash created and sent
	private String sdpHelloHashSent;
	// Synchronization lock
	private final Object lock = new Object();

	// error code to be sent
	private int errorCode;

	private RandomGenerator randomGenerator;
	// message types
	private static final byte[] MSG_TYPE_HELLO    = { 'H', 'e', 'l', 'l', 'o', ' ', ' ', ' ' };
	private static final byte[] MSG_TYPE_HELLOACK = { 'H', 'e', 'l', 'l', 'o', 'A', 'C', 'K' };
	private static final byte[] MSG_TYPE_COMMIT   = { 'C', 'o', 'm', 'm', 'i', 't', ' ', ' ' };
	private static final byte[] MSG_TYPE_DHPART1  = { 'D', 'H', 'P', 'a', 'r', 't', '1', ' ' };
	private static final byte[] MSG_TYPE_DHPART2  = { 'D', 'H', 'P', 'a', 'r', 't', '2', ' ' };
	private static final byte[] MSG_TYPE_CONFIRM1 = { 'C', 'o', 'n', 'f', 'i', 'r', 'm', '1' };
	private static final byte[] MSG_TYPE_CONFIRM2 = { 'C', 'o', 'n', 'f', 'i', 'r', 'm', '2' };
	private static final byte[] MSG_TYPE_CONF2ACK = { 'C', 'o', 'n', 'f', '2', 'A', 'C', 'K' };
	private static final byte[] MSG_TYPE_ERROR    = { 'E', 'r', 'r', 'o', 'r', ' ', ' ', ' ' };
	private static final byte[] MSG_TYPE_ERRORACK = { 'E', 'r', 'r', 'o', 'r', 'A', 'C', 'K' };
	private static final byte[] MSG_TYPE_GOCLEAR  = { 'G', 'O', 'C', 'L', 'E', 'A', 'R', ' ' };
	private static final byte[] MSG_TYPE_CLEARACK = { 'C', 'l', 'e', 'a', 'r', 'A', 'C', 'K' };
	private static final byte[] MSG_TYPE_SASRELAY = { 'S', 'A', 'S', 'r', 'e', 'l', 'a', 'y' };
	private static final byte[] MSG_TYPE_RELAYACK = { 'R', 'e', 'l', 'a', 'y', 'A', 'C', 'K' };
	private static final byte[] MSG_TYPE_PING     = { 'P', 'i', 'n', 'g', ' ', ' ', ' ', ' ' };
	private static final byte[] MSG_TYPE_PINGACK  = { 'P', 'i', 'n', 'g', 'A', 'C', 'K', ' ' };

	// prepared ACK messages
	private static final byte[] mMsgHelloACK = { 0x50, 0x5a, 0x00, 0x03, 'H', 'e', 'l', 'l', 'o', 'A', 'C', 'K' };
	private static final byte[] mMsgConf2ACK = { 0x50, 0x5a, 0x00, 0x03, 'C', 'o', 'n', 'f', '2', 'A', 'C', 'K' };
	private static final byte[] mMsgErrorACK = { 0x50, 0x5a, 0x00, 0x03, 'E', 'r', 'r', 'o', 'r', 'A', 'C', 'K' };

	// Commit message parts
	private static final byte[] AUTH_TYPE_32 = { 'H', 'S', '3', '2' };
	// shared secret MAC calculation constants
	private static final byte[] mResponderBytes = { 'R', 'e', 's', 'p', 'o', 'n', 'd', 'e', 'r' };
	private static final byte[] mInitiatorBytes = { 'I', 'n', 'i', 't', 'i', 'a', 't', 'o', 'r' };

	// our cache expiry value; we're always sending the recommened value 0xffffffff
	private static final byte[] mOurCacheExpiry = { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff };
	private static int counter = 0;
	private final Platform platform;

	private DiffieHellmanSuite dhSuite;

	/**
	 * Constructor
	 */
	public ZRTP(Platform platform) {
		this.platform = platform;
		randomGenerator = platform.getCrypto().getRandomGenerator();
		state = ZRTP_STATE_INACTIVE;
		errorCode = 0;
		retranTimer = new Timer();
		cache = new ZRTPCache(platform);
		delayedCacheUpdate = false;
		remoteTrust = false;
		securityWarningFlags = 0;
		hashChain = new HashChain();
		sdpHelloHashReceived = null;
		sdpHelloHashSent = "";
		dhSuite = platform.getCrypto().createDHSuite();
		dhSuite.setLogger(platform.getLogger());
		// ZID is created by ZRTPCache when we call getMyZid for the first time
		localZID = cache.getMyZid();

		/*
		 * Force client to be initiator or responder dependending on testing
		 * settigs
		 */
		/*
		 * forceToBeInitiator = TestSettings.TEST &&
		 * (TestSettings.TEST_ZRTP_WRONG_HMAC_COMMIT ||
		 * TestSettings.TEST_ZRTP_WRONG_HMAC_DHPART2);
		 */
		forceToBeResponder = TestSettings.TEST
				&& (TestSettings.TEST_ZRTP_WRONG_HMAC_DHPART1);
		/*
		 * if(forceToBeInitiator && forceToBeResponder) { logError(
		 * "TEST SETTINGS REQUIRE TO BE INITIATOR AND RESPONDER AT THE SAME TIME!!!"
		 * ); forceToBeInitiator = false; forceToBeResponder = false; }
		 */
	}

	private byte[] addImplicitHMAC(byte[] msg, byte[] key) {
		// Calculate HMAC for message and append it to message
		// ZRTP uses 8 byte HMACs in messages
		int authLen = msg.length;
		byte[] sha256hmac = createSHA256HMAC(msg, 0, authLen, key);
		byte[] newMsg = new byte[authLen + 8];
		System.arraycopy(msg, 0, newMsg, 0, authLen);
		System.arraycopy(sha256hmac, 0, newMsg, authLen, 8);
		return newMsg;
	}

	private long cacheExpiryTime() {
		if (cacheExpiry == 0xffffffffL) {
			return 0x7fffffffffffffffL;
		}
		if (cacheExpiry == 0) {
			return 0L;
		}
		return confirm1Timestamp + 1000L * (long) cacheExpiry;
	}

	private byte[] calculateS1() {
		// pre: iCache.selectEntry(iFarEndZID); has been called (in
		// createDHPartX)
		byte[] rs1 = cache.getRetainedSecret1();
		byte[] rs2 = cache.getRetainedSecret2();
		if (initiator) {
			byte[] rs1mac = (rs1 == null) ? null : createSHAHMAC(
					mResponderBytes, 0, mResponderBytes.length, rs1);
			if (rs1mac != null
					&& (platform.getUtils().equals(msgDhPart1RX, 44, rs1mac, 0,
							8) || platform.getUtils().equals(msgDhPart1RX, 52,
							rs1mac, 0, 8))) {
				if (platform.getLogger().isEnabled()) {
					logString("calculateS1: initiator - rs1; "
							+ platform.getUtils().equals(msgDhPart1RX, 44,
									rs1mac, 0, 8));
				}
				return rs1;
			}
			byte[] rs2mac = (rs2 == null) ? null : createSHAHMAC(
					mResponderBytes, 0, mResponderBytes.length, rs2);
			if (rs2mac != null
					&& (platform.getUtils().equals(msgDhPart1RX, 44, rs2mac, 0,
							8) || platform.getUtils().equals(msgDhPart1RX, 52,
							rs2mac, 0, 8))) {
				if (platform.getLogger().isEnabled()) {
					logString("calculateS1: initiator - rs2; "
							+ platform.getUtils().equals(msgDhPart1RX, 44,
									rs2mac, 0, 8));
				}
				return rs2;
			}
		} else {
			byte[] rs1mac = (rs1 == null) ? null : createSHAHMAC(
					mInitiatorBytes, 0, mInitiatorBytes.length, rs1);
			if (rs1mac != null
					&& platform.getUtils().equals(msgDhPart2RX, 44, rs1mac, 0,
							8)) {
				if (platform.getLogger().isEnabled()) {
					logString("calculateS1: responder - rs1 (a)");
				}
				return rs1;
			}
			byte[] rs2mac = (rs2 == null) ? null : createSHAHMAC(
					mInitiatorBytes, 0, mInitiatorBytes.length, rs2);
			if (rs2mac != null
					&& platform.getUtils().equals(msgDhPart2RX, 44, rs2mac, 0,
							8)) {
				if (platform.getLogger().isEnabled()) {
					logString("calculateS1: responder - rs2 (b)");
				}
				return rs2;
			}
			if (rs1mac != null
					&& platform.getUtils().equals(msgDhPart2RX, 52, rs1mac, 0,
							8)) {
				if (platform.getLogger().isEnabled()) {
					logString("calculateS1: responder - rs1 (c)");
				}
				return rs1;
			}
			if (rs2mac != null
					&& platform.getUtils().equals(msgDhPart2RX, 52, rs2mac, 0,
							8)) {
				if (platform.getLogger().isEnabled()) {
					logString("calculateS1: responder - rs2 (d)");
				}
				return rs2;
			}
		}

		if (rs1 != null || rs2 != null) {
			logWarning("calculateS1: Shared secret cache mismatch!");
			delayedCacheUpdate = true;
			raiseSharedSecretCacheMismatchWarning();
		} else {
			logString("calculateS1: no retained secrets.");
		}
		return null;
	}

	/**
	 * Calculate the hash digest of part of a message using the SHA256 algorithm
	 * 
	 * @param msg
	 *            Contents of the message
	 * @param offset
	 *            Offset of the data for the hash
	 * @param len
	 *            Length of msg to be considered for calculating the hash
	 * @return String of the hash in base 16
	 */
	private String calculateSHA256Hash(byte[] msg, int offset, int len) {
		// Calculate the SHA256 digest of the Hello message
		Digest digest = platform.getCrypto().createDigestSHA256();
		digest.update(msg, offset, len);
		int digestLen = digest.getDigestLength();
		// prepare space for hexadecimal representation, store the diggest in
		// the second half and then convert
		byte[] hash = new byte[2 * digestLen];
		digest.getDigest(hash, digestLen, true);
		for (int i = 0; i != digestLen; ++i) {
			byte b = hash[digestLen + i];
			int d1 = (b >> 4) & 0x0f;
			int d2 = b & 0x0f;
			hash[i * 2] = (byte) ((d1 >= 10) ? d1 + 'a' - 10 : d1 + '0');
			hash[i * 2 + 1] = (byte) ((d2 >= 10) ? d2 + 'a' - 10 : d2 + '0');
		}
		String hashStr = new String(hash);
		if (platform.getLogger().isEnabled()) {
			logBuffer("calculateSHA256Hash", msg, offset, len);
			logString("SHA256 Hash = '" + hashStr + "'");
		}
		return hashStr;
	}

	private void calculateSharedKeys() throws IOException {
		// Check if we have a shared secret to be used as s1, see ZRTP spec,
		// 4.3.
		// s1 = auxsecret and s2 = pbxsecret are not supported.
		s1 = calculateS1();
		if (ZRTP_461_FIX_TO_USE_S1_INSTEAD_OF_RS1 && s1 != null) {
			keepRS2 = s1;
		} else {
			keepRS2 = cache.getRetainedSecret1();
		}

		// DH Mode shared secret calculation, see ZRTP spec, 4.4.1.4
		// First generate the "total hash"
		Digest digest = createDigest(hashMode);
		if (initiator) {
			digest.update(rxHelloMsg);
			digest.update(msgCommitTX);
			digest.update(msgDhPart1RX);
			digest.update(msgDhPart2TX);
		} else {
			digest.update(txHelloMsg);
			digest.update(msgCommitRX);
			digest.update(msgDhPart1TX);
			digest.update(msgDhPart2RX);
		}
		totalHash = null;
		totalHash = new byte[digest.getDigestLength()];
		digest.getDigest(totalHash, 0, true);

		// Also generate the KDF Context here (ZRTP spec 4.4.1.4)
		kdfContext = new byte[24 + totalHash.length]; // ZIDi and ZIDr are
														// always 12 bytes each
		if (initiator) {
			System.arraycopy(localZID, 0, kdfContext, 0, 12);
			System.arraycopy(farEndZID, 0, kdfContext, 12, 12);
		} else {
			System.arraycopy(farEndZID, 0, kdfContext, 0, 12);
			System.arraycopy(localZID, 0, kdfContext, 12, 12);
		}
		System.arraycopy(totalHash, 0, kdfContext, 24, totalHash.length);
		if (platform.getLogger().isEnabled()) {
			logBuffer("iKDFContext: ", kdfContext);
		}

		// Now work out s0
		byte[] counter = { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01 };
		// Not actually a counter - just using same naming convention as in zrtp
		// spec
		digest.update(counter);
		digest.update(dhResult);
		String kdfString = "ZRTP-HMAC-KDF";
		digest.update(kdfString.getBytes());
		digest.update(kdfContext); // iKDFContext == ZIDi || ZIDr || total_hash
		byte[] nullLength = { (byte) 0x00, (byte) 0x00, (byte) 0x00,
				(byte) 0x00 };
		if (s1 == null) {
			digest.update(nullLength);
		} else {
			int len = s1.length;
			byte[] lenS1 = new byte[4];
			for (int i = 3; i >= 0; i--) {
				lenS1[i] = (byte) (len & 0xFF);
				len >>>= 8;
			}
			digest.update(lenS1);
			digest.update(s1);
		}
		if (s2 == null) {
			digest.update(nullLength);
		} else {
			int len = s2.length;
			byte[] lenS2 = new byte[4];
			for (int i = 3; i >= 0; i--) {
				lenS2[i] = (byte) (len & 0xFF);
				len >>>= 8;
			}
			digest.update(lenS2);
			digest.update(s2);
		}
		if (s3 == null) {
			digest.update(nullLength);
		} else {
			int len = s3.length;
			byte[] lenS3 = new byte[4];
			for (int i = 3; i >= 0; i--) {
				lenS3[i] = (byte) (len & 0xFF);
				len >>>= 8;
			}
			digest.update(lenS3);
			digest.update(s3);
		}
		s1 = s2 = s3 = null; // As per spec, must be removed after use
		s0 = null;
		s0 = new byte[digest.getDigestLength()];
		digest.getDigest(s0, 0, true);
		if (platform.getLogger().isEnabled()) {
			logBuffer("S0: ", s0);
		}

		// Now deriving the rest of the keys from s0 and KDF-Context (Section
		// 4.5.3)
		byte[] srtpKeyI = getKeyFromKDF(s0, "Initiator SRTP master key",
				kdfContext, 256); // TODO negotiated AES length
		byte[] srtpSaltI = getKeyFromKDF(s0, "Initiator SRTP master salt",
				kdfContext, 112);
		byte[] srtpKeyR = getKeyFromKDF(s0, "Responder SRTP master key",
				kdfContext, 256);// TODO negotiated AES length
		byte[] srtpSaltR = getKeyFromKDF(s0, "Responder SRTP master salt",
				kdfContext, 112);
		byte[] sasHash = getKeyFromKDF(s0, "SAS", kdfContext, 256);
		newRS = getKeyFromKDF(s0, "retained secret", kdfContext, 256);
		if (platform.getLogger().isEnabled()) {
			logBuffer("New retained secret: ", newRS);
		}

		sasString = sasMode.getShortAuthenticationStrings(sasHash);

		if (platform.getLogger().isEnabled()) {
			logString("calculateSharedKeys(), SAS: " + sasString);
		}

		if (initiator) {
			txMasterKey = srtpKeyI;
			txMasterSalt = srtpSaltI;
			rxMasterKey = srtpKeyR;
			rxMasterSalt = srtpSaltR;
		} else {
			txMasterKey = srtpKeyR;
			txMasterSalt = srtpSaltR;
			rxMasterKey = srtpKeyI;
			rxMasterSalt = srtpSaltI;
		}

		if (platform.getLogger().isEnabled()) {
			logBuffer("iTxMasterKey: ", txMasterKey);
			logBuffer("iTxMasterSalt: ", txMasterSalt);
			logBuffer("iRxMasterKey: ", rxMasterKey);
			logBuffer("iRxMasterSalt: ", rxMasterSalt);
		}
	}

	private boolean checkVersion(char major, char minor) throws IOException {
		// Checks protocol version is 1.1x
		// If its lower, send an error
		// If its higher just ignore
		// ZRTP spec 4.1.1
		boolean correctVer = true;
		boolean ignore = true;
		if (major != '1') {
			correctVer = false;
			if (major < '1') {
				ignore = false;
			}
		} else if (minor != '1') {
			correctVer = false;
			if (minor < '1') {
				ignore = false;
			}
		}
		if (!correctVer && !ignore) {
			sendError(ZRTP_ERROR_INCORRECT_VERSION);
		}
		return correctVer;
	}

	public boolean completed() {
		return completed;
	}

	private byte[] createConfirmMsg(boolean confirm1) throws CryptoException,
			IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		// first the encrypted portion
		int sigLen = 0;
		boolean e = false;
		boolean v = !delayedCacheUpdate && cache.getTrust();
		boolean a = false;
		boolean d = false;

		baos.write(hashChain.H0); // 8 words

		baos.write((byte) 0);
		baos.write((byte) ((sigLen >>> 8) & 0x1));
		baos.write((byte) (sigLen & 0xFF));
		baos.write((byte) ((d ? 1 : 0) | (a ? 2 : 0) | (v ? 4 : 0) | (e ? 8 : 0)));

		// cache expiration interval: 1 word
		baos.write(mOurCacheExpiry);

		byte[] cfbInitVector = randomGenerator.getBytes(16); // 4 words
        // TODO: AES key length.
		byte[] zrtpKey = getKeyFromKDF(s0, initiator 
		                                   ? "Initiator ZRTP key"
				                           : "Responder ZRTP key", kdfContext, 256);
		byte[] hmacKey = getKeyFromKDF(s0, initiator 
		                                   ? "Initiator HMAC key"
				                           : "Responder HMAC key", kdfContext, dhMode.hash.getLength());
		byte[] plainBytes = baos.toByteArray();
		if (platform.getLogger().isEnabled()) {
			logBuffer("Confirm plainBytes: ", plainBytes);
		}
		byte[] cipherBytes = platform.getCrypto().aesEncrypt(plainBytes,
				zrtpKey, cfbInitVector);

		ByteArrayOutputStream messageBaos = new ByteArrayOutputStream();
		// Now the header and the full packet
		messageBaos.write(createMessageBase(confirm1 ? MSG_TYPE_CONFIRM1 : MSG_TYPE_CONFIRM2, 32));
		byte[] hmac = createSHAHMAC(cipherBytes, 0, cipherBytes.length, hmacKey);
		if (TestSettings.TEST && TestSettings.TEST_ZRTP_WRONG_HMAC_CONFIRM) {
			randomGenerator.getBytes(hmac, 0, 2);
		}
		messageBaos.write(hmac, 0, 8); // 2 words
		messageBaos.write(cfbInitVector); // 4 words
		messageBaos.write(cipherBytes);
		byte[] messageBytes = messageBaos.toByteArray();
		if (platform.getLogger().isEnabled()) {
			logString("Total length in bytes: " + messageBytes.length);
		}
		int len = messageBytes.length / 4; // words
		messageBytes[2] = (byte) ((len >>> 8) & 0xFF);
		messageBytes[3] = (byte) (len & 0xFF);
		return messageBytes;
	}

	private byte[] createDHPartX(byte[] msgType)
			throws IllegalArgumentException, ZrtpException {
		int len = dhMode.pvLengthInWords + 21;
		byte[] dhPart = new byte[len * 4];
		System.arraycopy(createMessageBase(msgType, len), 0, dhPart, 0, 12);
		System.arraycopy(hashChain.H1, 0, dhPart, 12, 32);
		// add shared secret hashes
		cache.selectEntry(farEndZID);
		// Check cached phone number
		if (cache.getCurrentNumber() != null) {
			// Seen this zid before, make sure phone number is the same
			if (!platform.getAddressBook().matchingNumbers(
					cache.getCurrentNumber(), phoneNumber)) {
				// Phone number has changed, possible security breach
				logString("Found new Phone number for existing Remote ZID");
				/*
				 * It happens in two scenarios 1) my contact change legitimately
				 * his own phone number. 2) someone stolen my device and try to
				 * use it with his own SIM, eg: because I blocked my own
				 * 
				 * To avoid the dangerous second one, we raise a warning/hangup
				 * call
				 */
				cache.updateNumber(cacheExpiryTime(), phoneNumber);
				raiseDenialOfServiceWarning(null);
			}
		} else {
			if (cache.isNewZidForTrustedUser(phoneNumber)) {
				/*
				 * It happens in two scenarios 1) my contact reinstalled pgsm,
				 * creating a new ZID 2) a MITM call me using his own ZID and my
				 * contact Caller-ID. This could be dangerous if, knowing my
				 * contact (signaled in "incoming secure call popup") is
				 * trusted, I do not pay attention to phone display showing the
				 * untrusted status due to MITM presence
				 * 
				 * To avoid the dangerouse second one, we raise a warning/hangup
				 * call
				 */
				logString("Found new ZID for existing trusted user");
				raiseDenialOfServiceWarning(null);
			}
		}
		byte[] msg = (msgType == MSG_TYPE_DHPART2) ? mInitiatorBytes
				: mResponderBytes;
		writeSharedSecretID(dhPart, 44, msg, cache.getRetainedSecret1());
		writeSharedSecretID(dhPart, 52, msg, cache.getRetainedSecret2());
		writeSharedSecretID(dhPart, 60, hashChain.H3, null); // no auxsecret
		writeSharedSecretID(dhPart, 68, msg, null); // no pbxsecret
		dhSuite.setAlgorithm(dhMode);
		dhSuite.writePublicKey(dhPart, 76);
		byte[] shaHmac = createSHA256HMAC(dhPart, 0, len * 4 - 8, hashChain.H0);
		System.arraycopy(shaHmac, 0, dhPart, len * 4 - 8, 8);
		return dhPart;
	}

	private Digest createDigest(HashType hashType) {
		return HashType.SHA384.equals(hashType) ? (Digest) platform.getCrypto()
				.createDigestSHA384() : (Digest) platform.getCrypto()
				.createDigestSHA256();
	}

	private byte[] createHelloMsg() throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		int len = 3;
		baos.write(createMessageBase(MSG_TYPE_HELLO, len));
		baos.write(VERSION.getBytes());
		String clientID = new String(CLIENT_ID_RFC); // Must be 16 bytes
															// long
		baos.write(clientID.getBytes("US-ASCII"));
		baos.write(hashChain.H3);
		byte[] zid = localZID;
		if (TestSettings.TEST && TestSettings.TEST_ZRTP_ZID_COLLISION
				&& farEndZID != null) {
			// do not start sending Hello, but wait other peer's hello
			// in order to answer with the same ZID and trigger the ZID
			// collision
			zid = farEndZID;
		}
		baos.write(zid);
		String hashes = "";
		byte hc = 0;
		// Support for SHA-384 and SHA-256
		if (TestSettings.KEY_TYPE_EC38) {
			hashes += "S384";
			++hc;
		}
		if (TestSettings.KEY_TYPE_EC25 || TestSettings.KEY_TYPE_DH3K) {
			hashes += "S256";
			++hc;
		}
		String ciphers = new String("AES1AES3"); // AES-128 & 256
		String authTags = new String("HS32"); // HMAC-SHA1 32
		String keyTypes = "";
		byte kc = 0;
		if (TestSettings.KEY_TYPE_EC38) {
			keyTypes += "EC38";
			++kc;
		}
		if (TestSettings.KEY_TYPE_EC25) {
			keyTypes += "EC25";
			++kc;
		}

		if (TestSettings.KEY_TYPE_DH3K) {
			keyTypes += "DH3k";
			++kc;
		}
		String sasTypes = new String("B256"); // 32 bit & 256 bit sas supported
		// Signature type field will be length 0 as no signatures used
		baos.write(0x00); // SMP flags all set to zero
		baos.write(hc); // hc = hashes count
		baos.write(0x21); // cc = cypher count = 2, ac = auth tag count = 1
		baos.write((kc << 4) | 0x01); // kc = key agreement, sc = SAS count = 1
		baos.write(hashes.getBytes());
		baos.write(ciphers.getBytes());
		baos.write(authTags.getBytes());
		baos.write(keyTypes.getBytes());
		baos.write(sasTypes.getBytes());
		byte[] hello = baos.toByteArray();
		baos.close();

		// Now update the length indicator to correct number of 4 byte words
		len = hello.length >>> 2;
		len += 2; // Allow for HMAC
		hello[3] = (byte) (len & 0xFF);
		hello[2] = (byte) ((len >>> 8) & 0xFF);

		byte[] msg = addImplicitHMAC(hello, hashChain.H2);
		if (TestSettings.TEST && TestSettings.TEST_ZRTP_WRONG_HMAC_HELLO) {
			randomGenerator.getBytes(msg, hello.length, 2);
		}
		if (platform.isVerboseLogging()) {
			logBuffer("HELLO MSG:", msg);
		}
		return msg;
	}

	private byte[] createHvi() {
		// Create the hvi (hash value initiator), see zrtp spec 4.4.1.1
		try {
			if (dhPart2Msg == null) {
				dhPart2Msg = createDHPartX(MSG_TYPE_DHPART2);
			}
		} catch (Throwable ex) {
			logError("Error while creating DHPart2 when calculating HVI EX: "
					+ ex);
			ex.printStackTrace();
		}
		Digest digest = createDigest(hashMode);
		digest.update(dhPart2Msg, 0, dhPart2Msg.length);
		digest.update(rxHelloMsg, 0, rxHelloMsg.length);
		byte[] d = digest.getDigest();
		byte[] hvi = new byte[32];
		System.arraycopy(d, 0, hvi, 0, hvi.length);
		if (TestSettings.TEST && TestSettings.TEST_ZRTP_WRONG_HVI) {
			randomGenerator.getBytes(hvi, 0, 2);
		}
		return hvi;
	}

	private byte[] createMessageBase(byte[] msgType, int length)
			throws IllegalArgumentException {
		// Creates a base ZRTP message containing 2 byte header, 2 byte length &
		// 8 byte message
		// Supplied length is the number of 4 byte words to indicate in the
		// message length
		if ((msgType.length != 8) || (length < 3)) {
			logError("createMessage(), invalid parameter, string " + msgType
					+ ", length " + length);
			throw (new IllegalArgumentException());
		}
		byte[] ret = new byte[12];
		ret[0] = 0x50;
		ret[1] = 0x5A;
		ret[2] = (byte) ((length >>> 8) & 0xFF);
		ret[3] = (byte) (length & 0xFF);
		System.arraycopy(msgType, 0, ret, 4, 8);
		return (ret);
	}

	private byte[] createPingMsg() throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		int len = 3;
		baos.write(createMessageBase(MSG_TYPE_PING, len));
		baos.write(VERSION.getBytes());
		baos.write(randomGenerator.getBytes(8));
		byte[] msg = baos.toByteArray();
		baos.close();

		// Now update the length indicator to correct number of 4 byte words
		len = msg.length >>> 2;
		msg[3] = (byte) (len & 0xFF);
		msg[2] = (byte) ((len >>> 8) & 0xFF);
		return msg;

	}

	private byte[] createRemoteHvi(byte[] dhPart2Data, int offset, int len) {
		// Create the hvi (hash value initiator, see zrtp spec 4.4.1.1) that the
		// remote
		// client should have calculated. It's checked against the hvi received
		// in Commit.
		Digest digest = createDigest(hashMode);
		digest.update(dhPart2Data, offset, len);
		digest.update(txHelloMsg, 0, txHelloMsg.length);
		byte[] hvi = new byte[256]; // hvi is truncated to 256 bytes
		digest.getDigest(hvi, 0, false);
		return hvi;
	}

	private byte[] createSHA256Diggest(byte[] data, int offset, int length) {
		Digest digest = platform.getCrypto().createDigestSHA256();
		digest.update(data, offset, length);
		byte[] ret = new byte[32];
		digest.getDigest(ret, 0, false);
		return ret;
	}

	private byte[] createSHA256HMAC(byte[] data, int offset, int length,
			byte[] aKey) {
		return platform.getCrypto().calculateSHA256HMAC(data, offset, length,
				aKey);
	}

	private byte[] createSHAHMAC(byte[] data, int offset, int length,
			byte[] aKey) {
		return HashType.SHA384.equals(hashMode) ? platform.getCrypto()
				.calculateSHA384HMAC(data, offset, length, aKey) : platform
				.getCrypto().calculateSHA256HMAC(data, offset, length, aKey);
	}

	private void doClearACK(byte[] data, int offset, int len) {
		if (platform.getLogger().isEnabled()) {
			logString("Received ClearACK");
		}
		// TODO
		/*
		 * if (iState == ZRTP_STATE_GOCLEAR_SENT) { iRetranTask = null; }
		 */
	}

	private synchronized void doCommit(byte[] data, int offset, int len)
			throws IOException {
		if (len != 116) {
			logWarning("doCommit() received invalid length message");
			return;
		}
		if (msgCommitRX != null) {
			if (msgCommitRX.length != len
					|| !platform.getUtils().equals(msgCommitRX, 0, data,
							offset, len)) {
				raiseDenialOfServiceWarning("Commit message differs from the accepted Commit");
				return;
			}
		} else {
			if (!validateCommitMessage(data, offset)) {
				logWarning("doCommit received an invalid Commit message");
				logBuffer("COMMIT MSG", data, offset, len);
				return;
			}
			if (rxHelloMsg == null) {
				logWarning("doCommit received a Commit message before Hello, ignoring (can't validate h2 yet)");
				// this is a feasible scenario, don't issue a security warning
				return;
			}
			byte[] h2 = extractData(data, offset + 12, 32);
			byte[] h3 = createSHA256Diggest(h2, 0, 32);
			if (!platform.getUtils().equals(h3, 0, rxHelloMsg, 32, 32)) {
				raiseDenialOfServiceWarning("Commit H2 is not the preimage of the accepted Hello H3");
				return;
			}
			int helloMacOffset = rxHelloMsg.length - 8;
			byte[] helloMac = createSHA256HMAC(rxHelloMsg, 0, helloMacOffset,
					h2);
			if (!platform.getUtils().equals(helloMac, 0, rxHelloMsg,
					helloMacOffset, 8)) {
				raiseDenialOfServiceWarning("Using Commit H2 to hash the accepted Hello gives wrong MAC");
				return;
			}
		}
		if (state == ZRTP_STATE_SENDING_HELLO) {
			retranTask = null;
		}
		if ((state == ZRTP_STATE_SENDING_HELLO)
				|| (state == ZRTP_STATE_GOT_HELLO_ACK)) {
			// Far end will act as initiator
			logString("Received Commit, acting as responder, iState: "
					+ getStateText());
			commitMsg = extractData(data, offset, len);
			msgCommitRX = commitMsg;
			initiator = false;
			scheduleTimerResponderTimeout();
			state = ZRTP_STATE_GOT_COMMIT;
		} else if ((state == ZRTP_STATE_DHPART1_SENT)
				|| (state == ZRTP_STATE_GOT_COMMIT)) {
			// We're already in Got_Commit or dhpart1_sent states, our DHPart1
			// didn't arrive
			// so, send it again
			if (platform.getLogger().isEnabled()) {
				logString("Received Commit retransmission, iState: "
						+ getStateText());
			}
			state = ZRTP_STATE_GOT_COMMIT;
		} else if (state == ZRTP_STATE_COMMIT_SENT) {
			// if we've already received Commit and we're in commit_sent state,
			// we've already
			// performed commit contention.
			if (msgCommitRX == null) {
				msgCommitRX = extractData(data, offset, len);
				// Need to decide which end acts as initiator
				// Other end has sent Commit before receiving ours
				// (or the one we sent has got lost)
				logString("Received Commit, performing Commit Contention");
				// Since we only support DH mode, contention is based on
				// comparison of hvi
				int theirHviOffset = 76;
				byte[] ourHvi = createHvi();
				if (platform.isVerboseLogging()) {
					logBuffer("Our HVI:", ourHvi);
					logBuffer("Their HVI:", msgCommitRX, theirHviOffset, 32);
				}

				// hvi is treated as an unsigned integer for comparison (zrtp
				// spec 4.2)
				for (int i = 0; i < 32; i++) {
					int ourByte = ourHvi[i] & 0xFF;
					int theirByte = msgCommitRX[theirHviOffset + i] & 0xFF;
					if (ourByte > theirByte) {
						// Ours is bigger, so we act as initiator
						initiator = true;
						break;
					} else if (ourByte < theirByte) {
						// Far end is initiator
						commitMsg = msgCommitRX;
						initiator = false;
						state = ZRTP_STATE_GOT_COMMIT;
						// farEndH2 = null;
						// farEndH2 = extractData(msgCommitRX, 12, 32);
						if (commitMsg[59] == '4') {
							hashMode = HashType.SHA384;
						} else {
							hashMode = HashType.SHA256;
						}
						if (commitMsg[63] == '1') {
							// Already validated, so cipher string in bytes 60 -
							// 63
							// can only be "AES1" or "AES3"
							cipherInUse = CipherType.AES1;
						} else {
							cipherInUse = CipherType.AES3;
						}
						if (commitMsg[71] == '8') {
							// Already validated, so key agreement type in bytes
							// 68 - 71
							// can only be "EC25" or "DH3k"
							// iDHMode = DH_MODE_EC25;
							dhMode = KeyAgreementType.ECDH384;
							DH_MODE_EC_USE_256 = false;
						} else if (commitMsg[71] == '5') {
							dhMode = KeyAgreementType.ECDH256;
							DH_MODE_EC_USE_256 = true;
						} else {
							dhMode = KeyAgreementType.DH3K;
						}
						try {
							dhSuite.setAlgorithm(dhMode);
						} catch (Throwable t) {
							// TODO: handle exception
							logError("Creating keypair: " + t.getMessage());
						}
						scheduleTimerResponderTimeout();
						break;
					}
				}
				logString("We are initiator: " + initiator);
			} else {
				logString("Received Commit, commit contention already performed");
			}
		} else {
			// Not expecting to receive a Commit here
			// Probably just a retran that's taken a while to arrive
			// So, just ignore it
			logString("Unexpected Commit received, state = " + state);
		}

		if (state == ZRTP_STATE_GOT_COMMIT) {
			try {
				sendDHPart1();
				state = ZRTP_STATE_DHPART1_SENT;
			} catch (Throwable e) {
				logString("Exception while sending DHPart1, " + e.toString());
				sessionCompletedKO(ZrtpStrings.TEXT_ZRTP_ERROR_SENDING_DH);
			}
		}
	}

	private void doConf2ACK(byte[] data, int offset, int len) {
		if (platform.getLogger().isEnabled()) {
			logString("Received Conf2ACK");
		}
		if (state == ZRTP_STATE_CONFIRM2_SENT) {
			state = ZRTP_STATE_GOT_CONF2ACK;
			retranTask = null;
			if (!delayedCacheUpdate) {
				cache.updateEntry(cacheExpiryTime(), cache.getTrust(), newRS,
						keepRS2, phoneNumber);
			}
			sessionCompletedOK();
		}
	}

	private void doConfirm(byte[] data, int offset, int len)
			throws IOException, CryptoException {
		// header: 3 words
		byte[] initVector = extractData(data, offset + 20, 16); // 4 words
		byte[] zrtpKey = getKeyFromKDF(s0, !initiator ? "Initiator ZRTP key"
				: "Responder ZRTP key", kdfContext, 256);
		// plainBytes contains H0 (8 words), flags etc. (1 word) and cache
		// expiry (1 word)
		byte[] plainBytes = platform.getCrypto().aesDecrypt(data, offset + 36,
				len - 36, zrtpKey, initVector);
		if (platform.getLogger().isEnabled()) {
			logBuffer("Confirm plainBytes: ", plainBytes);
		}
		farEndH0 = new byte[32];
		System.arraycopy(plainBytes, 0, farEndH0, 0, 32);
		int sigLen = (plainBytes[33] & 0x1) << 8 + plainBytes[34];
		boolean d = (plainBytes[35] & 0x1) == 0x1;
		boolean a = (plainBytes[35] & 0x2) == 0x2;
		boolean v = (plainBytes[35] & 0x4) == 0x4;
		boolean e = (plainBytes[35] & 0x8) == 0x8;
		// We're always sending the recommened value 0xffffffff for cache
		// expiration interval, thus the
		// minimum of our and their interval is always their one.
		cacheExpiry = ((plainBytes[36] & 0xffL) << 24)
				+ ((plainBytes[37] & 0xffL) << 16)
				+ ((plainBytes[38] & 0xffL) << 8) + (plainBytes[39] & 0xffL);
		int optlen = len - 56; // the length of the optional part should be
								// sigLen*4, we're not checking
		logString("Confirm optlen=" + optlen + ";signLen=" + sigLen + ";d=" + d
				+ ";a=" + a + ";v=" + v + ";e=" + e + ";cacheExpiry="
				+ (((long) cacheExpiry) & 0xffffffff));
		remoteTrust = v;
		
		if (!remoteTrust) {
			cache.resetTrust(farEndZID);
		}

	}

	private void doConfirm1(byte[] data, int offset, int len)
			throws IOException, CryptoException {
		if (!initiator) {
			logString("Confirm1 received when not initiator");
			// TODO Do we need to send an error?
			return;
		}
		if (msgConfirm1RX != null) {
			if (msgConfirm1RX.length != len
					|| !platform.getUtils().equals(msgConfirm1RX, 0, data,
							offset, len)) {
				raiseDenialOfServiceWarning("Confirm1 message differs from the accepted Confirm1");
				return;
			}
			if (platform.getLogger().isEnabled()) {
				logString("Received Confirm1 retransmission");
			}
			return;
		}
		if (state != ZRTP_STATE_DHPART2_SENT) {
			logString("Received unexpected Confirm1 Message, state = " + state);
			return;
		}
		if (len < 56) {
			logString("Received too short Confirm1, length " + len);
			return;
		}
		if (platform.getLogger().isEnabled()) {
			logString("Received Confirm1");
		}
		confirm1Timestamp = System.currentTimeMillis();
		doConfirm(data, offset, len);
		// validate h1 from DHPart1
		byte[] h1 = createSHA256Diggest(farEndH0, 0, 32);
		if (!platform.getUtils().equals(h1, 0, msgDhPart1RX, 12, 32)) {
			raiseDenialOfServiceWarning("Confirm1 H0 is not the preimage of the accepted DHPart1 H1");
			return;
		}
		int dhPart1MacOffset = msgDhPart1RX.length - 8;
		byte[] dhPart1Mac = createSHA256HMAC(msgDhPart1RX, 0, dhPart1MacOffset,
				farEndH0);
		if (!platform.getUtils().equals(dhPart1Mac, 0, msgDhPart1RX,
				dhPart1MacOffset, 8)) {
			raiseDenialOfServiceWarning("Using Commit1 H0 to hash the accepted DHPart1 gives wrong MAC");
			return;
		}
		// check confirm_mac
		byte[] hmacKey = getKeyFromKDF(s0, "Responder HMAC key", kdfContext,
				dhMode.hash.getLength());
		byte[] confirm_mac = createSHAHMAC(data, offset + 36, len - 36, hmacKey);
		if (!platform.getUtils().equals(confirm_mac, 0, data, offset + 12, 8)) {
			raiseDenialOfServiceWarning("Confirm1 has wrong confirm_mac");
			return;
		}
		retranTask = null;
		msgConfirm1RX = extractData(data, offset, len);
		sendConfirm2();
		boolean success = listener.keyExchangeCompleted(txMasterKey,
				txMasterSalt, rxMasterKey, rxMasterSalt, seqNum);
		if (!success) {
			sessionCompletedKO(ZrtpStrings.TEXT_ZRTP_CONFIRM);
			return;
		}
		state = ZRTP_STATE_CONFIRM2_SENT;
	}

	private void doConfirm2(byte[] data, int offset, int len)
			throws IOException, CryptoException {
		if (initiator) {
			logString("Confirm2 received when initiator");
			// TODO Do we need to send an error?
			return;
		}
		if (msgConfirm2RX != null) {
			if (msgConfirm2RX.length != len
					|| !platform.getUtils().equals(msgConfirm2RX, 0, data,
							offset, len)) {
				raiseDenialOfServiceWarning("Confirm2 message differs from the accepted Confirm2");
				return;
			}
			if (platform.getLogger().isEnabled()) {
				logString("Received Confirm2 retransmission");
			}
			sendZrtpPacket(mMsgConf2ACK);
			return;
		}
		if (state != ZRTP_STATE_CONFIRM1_SENT) {
			logString("Received unexpected Confirm2 Message, state = " + state);
			return;
		}
		if (len < 56) {
			logString("Received too short Confirm2, length " + len);
			return;
		}
		if (platform.getLogger().isEnabled()) {
			logString("Received Confirm2");
		}
		doConfirm(data, offset, len);
		// validate h1 from DHPart1
		byte[] h1 = createSHA256Diggest(farEndH0, 0, 32);
		if (!platform.getUtils().equals(h1, 0, msgDhPart2RX, 12, 32)) {
			raiseDenialOfServiceWarning("Confirm2 H0 is not the preimage of the accepted DHPart2 H1");
			return;
		}
		int dhPart2MacOffset = msgDhPart2RX.length - 8;
		byte[] dhPart2Mac = createSHA256HMAC(msgDhPart2RX, 0, dhPart2MacOffset,
				farEndH0);
		if (!platform.getUtils().equals(dhPart2Mac, 0, msgDhPart2RX,
				dhPart2MacOffset, 8)) {
			raiseDenialOfServiceWarning("Using Commit2 H0 to hash the accepted DHPart2 gives wrong MAC");
			return;
		}
		// check confirm_mac
		byte[] hmacKey = getKeyFromKDF(s0, "Initiator HMAC key", kdfContext,
				dhMode.hash.getLength());
		byte[] confirm_mac = createSHAHMAC(data, offset + 36, len - 36, hmacKey);
		if (!platform.getUtils().equals(confirm_mac, 0, data, offset + 12, 8)) {
			raiseDenialOfServiceWarning("Confirm2 has wrong confirm_mac");
			return;
		}
		s0 = null; // we're done with s0, clear as required by ZRTP spec,
					// section 4.6.1
		if (!delayedCacheUpdate) {
			cache.updateEntry(cacheExpiryTime(), cache.getTrust(), newRS,
					keepRS2, phoneNumber);
		}
		msgConfirm2RX = extractData(data, offset, len);
		sendConf2ACK();
		state = ZRTP_STATE_CONF2ACK_SENT;
	}

	private void doDHPart1(byte[] data, int offset, int len)
			throws IOException, ZrtpException {
		if (state == ZRTP_STATE_COMMIT_SENT) {
			retranTask = null;
		}
		if (msgDhPart1RX != null) {
			if (msgDhPart1RX.length != len
					|| !platform.getUtils().equals(msgDhPart1RX, 0, data,
							offset, len)) {
				raiseDenialOfServiceWarning("DHPart1 message differs from the accepted DHPart1");
				return;
			}
			if (platform.getLogger().isEnabled()) {
				logString("Received DHPart1 retransmission");
			}
			return;
		}
		if (!initiator) {
			logWarning("DHPart1 received when not initiator");
			// TODO Do we need to send an error?
			return;
		}
		if (state != ZRTP_STATE_COMMIT_SENT) {
			logWarning("Received unexpected DHPart1 Message, state = " + state);
			return;
		}
		// Validate length (will be 148 (EC25 mode) or 468 (DH3K mode))
		// Validate length (will be 180 (EC38 mode) or 468 (DH3K mode))
		int expectedLen = (dhMode.pvLengthInWords + 21) * 4;
		if (len != expectedLen) {
			logWarning("DHPart1 received with invalid length, " + len
					+ " in mode " + dhMode);
			return;
		}
		// validate h3 from h1 (h2 in commit may not have been received, we're
		// ignoring it if it was)
		byte[] h2 = createSHA256Diggest(data, offset + 12, 32);
		byte[] h3 = createSHA256Diggest(h2, 0, 32);
		if (!platform.getUtils().equals(h3, 0, rxHelloMsg, 32, 32)) {
			raiseDenialOfServiceWarning("DHPart1 H1 is not the second preimage of the accepted Hello H3");
			return;
		}
		int helloMacOffset = rxHelloMsg.length - 8;
		byte[] helloMac = createSHA256HMAC(rxHelloMsg, 0, helloMacOffset, h2);
		if (!platform.getUtils().equals(helloMac, 0, rxHelloMsg,
				helloMacOffset, 8)) {
			raiseDenialOfServiceWarning("Using H2 calculated from DHPart1 H1 to hash the accepted Hello gives wrong MAC");
			return;
		}
		if (platform.getLogger().isEnabled()) {
			logString("Processing DHPart1.....");
		}
		msgDhPart1RX = extractData(data, offset, len);
		// farEndH1 = extractData(msgDhPart1RX, 12, 32);
		dhResult = null;
		getDHResult(msgDhPart1RX);
		if (dhResult == null) {
			msgDhPart1RX = null;
			return;
		}
		sendDHPart2();
		calculateSharedKeys();
		state = ZRTP_STATE_DHPART2_SENT;
	}

	private void doDHPart2(byte[] data, int offset, int len)
			throws IOException, CryptoException {
		logString("Received DHPart2");
		if (initiator) {
			logString("DHPart2 received when initiator");
			// TODO Do we need to send an error?
			return;
		}
		logString("Received DHPart2 - not initiator");
		if (msgDhPart2RX != null) {
			logString("Received DHPart2 - not null");
			if (msgDhPart2RX.length != len
					|| !platform.getUtils().equals(msgDhPart2RX, 0, data,
							offset, len)) {
				raiseDenialOfServiceWarning("DHPart2 message differs from the accepted DHPart2");
				return;
			}
			if (platform.getLogger().isEnabled()) {
				logString("Received DHPart2 retransmission");
			}
			sendZrtpPacket(msgConfirm1TX);
			return;
		}
		if (state != ZRTP_STATE_DHPART1_SENT) {
			logString("Received unexpected DHPart2 Message, state = " + state);
			return;
		}
		// check h2 from commit
		byte[] h1 = extractData(data, offset + 12, 32);
		byte[] h2 = createSHA256Diggest(h1, 0, 32);
		if (!platform.getUtils().equals(h2, 0, msgCommitRX, 12, 32)) {
			platform.getLogger().logWarning(
					"doDHPart2 security warning: invalid hash preimage");
			raiseDenialOfServiceWarning("DHPart2 H1 is not the preimage of the accepted Commit H2");
			return;
		}
		int commitMacOffset = msgCommitRX.length - 8;
		byte[] commitMac = createSHA256HMAC(msgCommitRX, 0, commitMacOffset, h1);
		if (!platform.getUtils().equals(commitMac, 0, msgCommitRX,
				commitMacOffset, 8)) {
			raiseDenialOfServiceWarning("Using DHPart2 H1 to hash the accepted Commit gives wrong MAC");
			return;
		}
		// check hvi from commit
		byte[] hvi = createRemoteHvi(data, offset, len);
		int commitHviOffset = commitMacOffset - 32; // 32 = 8 words, hvi length
		if (!platform.getUtils().equals(hvi, 0, msgCommitRX, commitHviOffset,
				32)) { // 32 = 8 words, hvi length
			raiseDenialOfServiceWarning("HVI calculated from incoming DHPart2 and our Hello doesn't match Commit HVI");
			return;
		}
		if (platform.getLogger().isEnabled()) {
			logString("Processing DHPart2.....");
		}
		msgDhPart2RX = extractData(data, offset, len);
		dhResult = null;
		getDHResult(msgDhPart2RX);
		if (dhResult == null) {
			msgDhPart2RX = null;
			return;
		}
		calculateSharedKeys();
		sendConfirm1();
		state = ZRTP_STATE_CONFIRM1_SENT;
	}

	private void doError(byte[] data, int offset, int len) {
		if (len != 16) {
			logString("Received Error message with invalid length " + len);
			return;
		}

		logBuffer("Received Error - Terminating Session", data, offset, len);
		int errCode = platform.getUtils().getInt(data, offset, offset + len); // data[offset+15]
																				// +
																				// (data[offset+14]
																				// <<
																				// 8);
		logError("Received Error Code " + getZrtpErrorName(errCode));
		try {
			sendErrorACK();
		} catch (Throwable e) {
			logError("Problem occurred sending ErrorACK Message");
			// Not much we can do if here, just allow the session to be
			// completed
		}
		sessionCompletedKO(ZrtpStrings.TEXT_ZRTP_ERROR,
				getZrtpErrorName(errCode));
	}

	private void doErrorACK(byte[] data, int offset, int len) {
		if (platform.getLogger().isEnabled()) {
			logString("Received ErrorACK");
		}
		if (errorCode != 0) {
			errorCode = 0;
			retranTask = null;
		}
	}

	private void doGoClear(byte[] data, int offset, int len) {
		if (platform.getLogger().isEnabled()) {
			logString("Received GoClear");
		}
	}

	private void doHello(byte[] data, int offset, int len) throws IOException {
		/*
		 * Format of hello is Byte 00 - 11 Header & message type 12 - 15
		 * Protocol version 16 - 31 Client Identifier 32 - 63 Hash image H3 64 -
		 * 75 ZID 76 - 79 Algorithm list header 80 onwards Algorithm list
		 */
		// handleIncomingMessage already verified that len==wordCount*4
		if (platform.getLogger().isEnabled()) {
			logString("Received Hello, word length " + (len >> 2));
		}
		if (len < 80) {
			logString("Ignoring Hello, message too short");
			return;
		}
		if (rxHelloMsg != null) {
			if (rxHelloMsg.length != len
					|| !platform.getUtils().equals(rxHelloMsg, 0, data, offset,
							len)) {
				raiseDenialOfServiceWarning("Hello message differs from the accepted Hello");
				return;
			}
			// Already seen the Hello message, just ACK it & move on
			sendHelloACK();
		} else {
			byte[] aMsg = extractData(data, offset, len);
			// If the received Hello msg doesn't have the same hash as sent in
			// the SDP
			// it could be tweaked by a middle man so ignore it
			if (!verifyHelloMessage(aMsg)) {
				raiseDenialOfServiceWarning("Hello H3 does not match zrtp-hash");
				return;
			}
			if (!checkVersion((char) aMsg[12], (char) aMsg[14])) {
				logWarning("doHello Ignoring Hello msg, version check failed! version major='"
						+ ((char) aMsg[12])
						+ "' mid='"
						+ ((char) aMsg[13])
						+ "' minor='" + ((char) aMsg[14]) + "'");
				return;
			}
			farEndClientID = new String(extractData(aMsg, 16, 16), "US-ASCII");
			logString("HELLO - FarEndClientID " + farEndClientID);
			// farEndH3 = extractData(aMsg, 32, 32);
			farEndZID = extractData(aMsg, 64, 12);
			int hashCount = aMsg[77] & 0x0F;
			int cipherCount = (aMsg[78] >>> 4) & 0x0F;
			int authCount = aMsg[78] & 0x0F;
			int keyCount = (aMsg[79] >>> 4) & 0x0F;
			int sasCount = aMsg[79] & 0x0F;
			int hashPos = 80;
			int cipherPos = hashPos + (hashCount * 4);
			int authPos = cipherPos + (cipherCount * 4);
			int keyPos = authPos + (authCount * 4);
			int sasPos = keyPos + (keyCount * 4);
			boolean isLegacyAttributeList = false;
			hashMode = HashType.SHA256;
			
			for (int i = 0; i < hashCount; i++) {
				// Only need to check for SHA-384 as, if its not there, we'll
				// always use SHA-256
				if (DH_MODE_EC_USE_256 && TestSettings.KEY_TYPE_EC25) {
					if (platform.getUtils().equals(HashType.SHA256.getType(),
							0, aMsg, hashPos + i * 4, 4)) {
						hashMode = HashType.SHA256;
					}
				} else if (!DH_MODE_EC_USE_256 && TestSettings.KEY_TYPE_EC38) {
					if (platform.getUtils().equals(HashType.SHA384.getType(),
							0, aMsg, hashPos + i * 4, 4)) {
						hashMode = HashType.SHA384;
					}
				}
				if (platform.isVerboseLogging()) {
					logString("HELLO MSG - HASH: "
							+ new String(aMsg, hashPos + i * 4, 4));
				}
			}
			
			isLegacyAttributeList = LegacyClientUtils.checkHash(platform ,aMsg, hashPos, hashCount);

			// If cipherCount == 0, only supports mandatory AES-128
			cipherInUse = CipherType.AES1;
			for (int i = 0; i < cipherCount; i++) {
				// Only need to check for AES3 as, if its not there, we'll
				// always use AES1
				if (platform.getUtils().equals(CipherType.AES3.getType(), 0,
						aMsg, cipherPos + i * 4, 4)) {
					cipherInUse = CipherType.AES3;
				}
				if (platform.isVerboseLogging()) {
					logString("HELLO MSG - CIPHER: "
							+ new String(aMsg, cipherPos + i * 4, 4));
				}

			}
			
			isLegacyAttributeList &= LegacyClientUtils.checkCipher(platform ,aMsg, cipherPos, cipherCount);
			
			// If keyCount == 0, only supports mandatory DH3K
			dhMode = KeyAgreementType.DH3K;
			for (int i = 0; i < keyCount; i++) {
				if (DH_MODE_EC_USE_256 && TestSettings.KEY_TYPE_EC25) {
					if (platform.getUtils().equals(
							KeyAgreementType.ECDH256.getType(), 0, aMsg,
							keyPos + i * 4, 4)) {
						dhMode = KeyAgreementType.ECDH256;
					}
				} else if (!DH_MODE_EC_USE_256 && TestSettings.KEY_TYPE_EC38) {
					if (platform.getUtils().equals(
							KeyAgreementType.ECDH384.getType(), 0, aMsg,
							keyPos + i * 4, 4)) {
						dhMode = KeyAgreementType.ECDH384;
					}
				}
				if (platform.isVerboseLogging()) {
					logString("HELLO MSG - KEY: "
							+ new String(aMsg, keyPos + i * 4, 4));
				}
			}
			dhSuite.setAlgorithm(dhMode);
			
			isLegacyAttributeList &= LegacyClientUtils.checkKeyAgreement(platform ,aMsg, keyPos, keyCount);
			
			// If sasCount == 0, only supports mandatory B32 SAS
			sasMode = SasType.B32;
			for (int i = 0; i < sasCount; i++) {
				// Only need to check for B256 as, if its not there, we'll
				// always use B32
				if (platform.getUtils().equals(SasType.B256.getType(), 0, aMsg,
						sasPos + i * 4, 4)) {
					sasMode = SasType.B256;
				}
				if (platform.isVerboseLogging()) {
					logString("HELLO MSG - SAS: "
							+ new String(aMsg, sasPos + i * 4, 4));
				}
			}
			
			isLegacyAttributeList &= LegacyClientUtils.checkSasAgreement(platform ,aMsg, sasPos, sasCount);
			
			/* the last check, with ClientID */
			
			isLegacyClient = LegacyClientUtils.checkClientId(isLegacyAttributeList, farEndClientID);


			try {
				if (dhPart2Msg == null) {
					dhPart2Msg = createDHPartX(MSG_TYPE_DHPART2);
				}
			} catch (Throwable ex) {
				logError("Error at doHello() when creating DHPart2 EX: " + ex);
				ex.printStackTrace();
			}
			rxHelloMsg = aMsg;
			sendHelloACK();
		}
	}

	private synchronized void doHelloACK(byte[] data, int offset, int len)
			throws IOException {
		if (platform.getLogger().isEnabled()) {
			logString("Received HelloACK");
		}
		if (state == ZRTP_STATE_SENDING_HELLO) {
			// Because of network issues, this could arrive after a Commit
			// So, ignore it in all other states
			retranTask = null;
			state = ZRTP_STATE_GOT_HELLO_ACK;
			if (rxHelloMsg != null) {
				// We've received a valid hello & far end has ACKed ours
				// Send a commit as we've not received one yet
				if (forceToBeResponder) {
					// nothing to do. Do not send COMMIT yet, and wait COMMIT
					// from other
					// peer so that we will be responder
				} else {
					initiator = true; // This might change if we receive a
										// Commit and have to do contention
					sendCommit();
					state = ZRTP_STATE_COMMIT_SENT;
				}
			}
		}
	}

	private void doPing(byte[] data, int offset, int len) {
		if (platform.getLogger().isEnabled()) {
			logString("Received Ping");
		}
	}

	private void doPingACK(byte[] data, int offset, int len) {
		if (platform.getLogger().isEnabled()) {
			logString("Received PingACK");
		}
	}

	private void doRelayACK(byte[] data, int offset, int len) {
		if (platform.getLogger().isEnabled()) {
			logString("Received RelayACK");
		}
	}

	private void doSASrelay(byte[] data, int offset, int len) {
		if (platform.getLogger().isEnabled()) {
			logString("Received SASrelay");
		}
		// TODO
		/*
		 * if (iState == ZRTP_STATE_SASRELAY_SENT) { iRetranTask = null; }
		 */
	}

	private void endSession() {
		// For trust() and untrust() to work after the session has terminated we
		// must keep
		// iCache, iNewRS, iKeepRS2, iCacheExpiry, iConfirm1Timestamp and
		// iDelayedCacheUpdate.
		// iFarEndZID is not necessary as the cache has the correct ZID already
		// selected.
		retranTimer.cancel();
		retranTask = null;
		started = false;
		// iRtpSender = null; // keep RTP sender for responding to Confirm2
		// retransmissions
		completed = true;
		if (hashChain != null)
			hashChain.clear();
		initiator = false;
		dhPart1Msg = dhPart2Msg = null;
		rxHelloMsg = txHelloMsg = null;
		msgCommitRX = msgCommitTX = null;
		msgDhPart1RX = msgDhPart1TX = null;
		msgDhPart2RX = msgDhPart2TX = null;
		commitMsg = null;
		farEndZID = null;
		farEndH0 = null;
		farEndClientID = "";
		isLegacyClient = false;
		// farEndH1 = null;
		// farEndH2 = null;
		// farEndH3 = null;
		if (dhSuite != null) {
			dhSuite.clear();
			dhSuite = null;
		}
	}

	private byte[] extractData(byte[] src, int offset, int len) {
		byte[] ret = new byte[len];
		System.arraycopy(src, offset, ret, 0, len);
		return ret;
	}

	private void getDHResult(byte[] msg) throws ZrtpException {
		if (platform.getLogger().isEnabled()) {
			logString("Received DHPart1 or DHPart2 using" + dhMode);
		}
		dhResult = dhSuite.getDhResult(msg, 76 ,isLegacyClient);
	}

	/**
	 * @return SHA256 Hash of the Hello message to be included in the SDP See:
	 *         draft-zimmermann-avt-zrtp-17 Sections: 4.1, 8.1 & 5.1.2.1
	 */
	public String getHelloHash() throws IOException {
		if (!hashChain.helloHashCreated) {
			// Create hello message
			byte[] msg = createHelloMsg();
			// Calculate the SHA256 hash of the created Hello message
			// Use Implicit Hash (SHA-256) and not Negotiated Hash
			sdpHelloHashSent = calculateSHA256Hash(msg, 0, msg.length);
			hashChain.helloHashCreated = true;
		}
		return sdpHelloHashSent;
	}

	/**
	 * Generate key/salt pairs for SRTP using the S0 and KDF_Context provided
	 * (Section 4.5.3)
	 * 
	 * @param ki
	 *            S0
	 * @param label
	 *            Text string used in key/salt generation
	 * @param context
	 *            KDF_Context
	 * @param l
	 *            Length of the key/salt in bits
	 * @return Key/salt with length of aL bits. If aL is smaller than 256, the
	 *         32 bits result is truncated and aL leftmost bits are returned as
	 *         specified in section 4.5.3.
	 * @throws IOException
	 */
	private byte[] getKeyFromKDF(byte[] ki, String label, byte[] context, int l)
			throws IOException {
		int bytesCount = l >>> 3;
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		byte[] counter = new byte[] { (byte) 0x00, (byte) 0x00, (byte) 0x00,
				(byte) 0x01 };
		baos.write(counter);
		baos.write(label.getBytes());
		baos.write((byte) 0x00);
		baos.write(context);
		byte[] len = new byte[4];
		for (int i = 3; i >= 0; i--) {
			len[i] = (byte) (l & 0xFF);
			l >>>= 8;
		}
		baos.write(len);
		byte[] array = baos.toByteArray();
		baos.close();
		byte[] hmac = createSHAHMAC(array, 0, array.length, ki);
		// Create a new result array of aL bits
		byte[] result = new byte[bytesCount];
		// Copy aL leftmost bits of the HMAC
		System.arraycopy(hmac, 0, result, 0, bytesCount);
		return result;
	}

	public String getSasString() {
		if (sasString == null) {
			return "";
		}
		return sasString;
	}

	private int getStartSeqNum() {
		return randomGenerator.getInt() & 0xffff;
	}

	private String getStateText() {
		switch (state) {
		case ZRTP_STATE_INACTIVE:
			return "ZRTP_STATE_INACTIVE";
		case ZRTP_STATE_SENDING_HELLO:
			return "ZRTP_STATE_SENDING_HELLO";
		case ZRTP_STATE_GOT_HELLO_ACK:
			return "ZRTP_STATE_GOT_HELLO_ACK";
		case ZRTP_STATE_GOT_COMMIT:
			return "ZRTP_STATE_GOT_COMMIT";
		case ZRTP_STATE_COMMIT_SENT:
			return "ZRTP_STATE_COMMIT_SENT";
		case ZRTP_STATE_GOT_DHPART1:
			return "ZRTP_STATE_GOT_DHPART1";
		case ZRTP_STATE_DHPART1_SENT:
			return "ZRTP_STATE_DHPART1_SENT";
		case ZRTP_STATE_GOT_DHPART2:
			return "ZRTP_STATE_GOT_DHPART2";
		case ZRTP_STATE_DHPART2_SENT:
			return "ZRTP_STATE_DHPART2_SENT";
		case ZRTP_STATE_GOT_CONFIRM1:
			return "ZRTP_STATE_GOT_CONFIRM1";
		case ZRTP_STATE_CONFIRM1_SENT:
			return "ZRTP_STATE_CONFIRM1_SENT";
		case ZRTP_STATE_GOT_CONFIRM2:
			return "ZRTP_STATE_GOT_CONFIRM2";
		case ZRTP_STATE_CONFIRM2_SENT:
			return "ZRTP_STATE_CONFIRM2_SENT";
		case ZRTP_STATE_GOT_CONF2ACK:
			return "ZRTP_STATE_GOT_CONF2ACK";
		case ZRTP_STATE_CONF2ACK_SENT:
			return "ZRTP_STATE_CONF2ACK_SENT";
		default:
			return "N/A [" + state + "]";
		}
	}

	private String getZrtpErrorName(int errCode) {
		switch (errCode) {
		case ZRTP_ERROR_BAD_CONFIRM_HMAC:
			return "BAD CONFIRM HMAC";
		case ZRTP_ERROR_CRITICAL_SW_FAULT:
			return "CRITICAL SW FAULT";
		case ZRTP_ERROR_DH_BAD_PVI:
			return "DH BAD PVI";
		case ZRTP_ERROR_DH_HVI_WRONG:
			return "DH HVI WRONG";
		case ZRTP_ERROR_EQUAL_ZIDS_IN_HELLO:
			return "EQUALS ZIDS IN HELLO";
		case ZRTP_ERROR_HELLO_MISMATCH:
			return "HELLO MISMATCH";
		case ZRTP_ERROR_INCORRECT_VERSION:
			return "INCORRECT VERSION";
		case ZRTP_ERROR_MALFORMED_PACKET:
			return "MALFORMED PACKET";
		case ZRTP_ERROR_NONCE_REUSED:
			return "NONCE REUSED";
		case ZRTP_ERROR_PROTOCOL_TIMEOUT:
			return "PROTOCOL TIMEOUT";
		case ZRTP_ERROR_SERVICE_UNAVAILABLE:
			return "SERVICE UNAVAILABLE";
		case ZRTP_ERROR_UNALLOWED_GO_CLEAR_RCVD:
			return "UNALLOWED GO CLEAR RCVD";
		case ZRTP_ERROR_UNAVAILABLE_SHARED_SECRET:
			return "UNAVAILABLE SHARED SECRET";
		case ZRTP_ERROR_UNSUPPORTED_CIPHER:
			return "UNSUPPORTED CIPHER";
		case ZRTP_ERROR_UNSUPPORTED_HASH:
			return "UNSUPPORTED HASH";
		case ZRTP_ERROR_UNSUPPORTED_KEY_EXCHANGE:
			return "UNSUPPORTED KEY EXCHANGE";
		case ZRTP_ERROR_UNSUPPORTED_SAS_SCHEME:
			return "UNSUPPORTED SAS SCHEME";
		case ZRTP_ERROR_UNSUPPORTED_SRTP_AUTH:
			return "UNSUPPORTED SRTP AUTH";
		case ZRTP_ERROR_UNTRUSTED_SAS:
			return "UNTRUSTED SAS";
		default:
			return "UNKNOWN(" + errCode + ")";
		}
	}

	/**
	 * Handle an incoming ZRTP message. Assumes RTP headers and trailing CRC
	 * have been stripped by caller
	 * 
	 * @param aMsg
	 *            byte array containing the ZRTP message
	 */
	public void handleIncomingMessage(byte[] data, int offset, int len) {
		lastPacketArrival = System.currentTimeMillis();
		if (platform.isVerboseLogging()) {
			logZrtpMessage("ZRTP received", data, offset, len);
		}
		if (!started) {
			logBuffer(
					"handleIncomingMessage(), received message when not started",
					data, offset, len);
			return;
		}
		if (len < 12) {
			// Too short, must have at least 2 byte header (0x505A), 2 byte
			// length indicator
			// and 8 byte message type
			logBuffer("handleIncomingMessage(), received message too short",
					data, offset, len);
			return;
		}
		if ((data[offset + 0] != 0x50) || (data[offset + 1] != 0x5A)) {
			logBuffer(
					"handleIncomingMessage(), received invalid message header 0x"
							+ Integer.toHexString((data[offset + 1] << 8)
									+ data[offset + 0]), data, offset, len);
			return;
		}
		// Length in message is number of 4 byte words
		int msgLen = (data[offset + 2] << 8) + data[offset + 3];
		if (len != msgLen * 4) {
			logBufferWarning(
					"handleIncomingMessage(), received message with wrong length defined in header as "
							+ msgLen
							+ " words"
							+ " ("
							+ (msgLen * 4)
							+ " bytes) but have an array of " + len + " bytes",
					data, offset, len);
			return;
		}
		int mtOff = offset + 4; /* message type offset */
		try {
			if (platform.getUtils().equals(data, mtOff, MSG_TYPE_HELLO, 0, 8)) {
				doHello(data, offset, len);
			} else if (platform.getUtils().equals(data, mtOff,
					MSG_TYPE_HELLOACK, 0, 8)) {
				doHelloACK(data, offset, len);
			} else if (platform.getUtils().equals(data, mtOff, MSG_TYPE_COMMIT,
					0, 8)) {
				doCommit(data, offset, len);
			} else if (platform.getUtils().equals(data, mtOff,
					MSG_TYPE_DHPART1, 0, 8)) {
				doDHPart1(data, offset, len);
			} else if (platform.getUtils().equals(data, mtOff,
					MSG_TYPE_DHPART2, 0, 8)) {
				doDHPart2(data, offset, len);
			} else if (platform.getUtils().equals(data, mtOff,
					MSG_TYPE_CONFIRM1, 0, 8)) {
				doConfirm1(data, offset, len);
			} else if (platform.getUtils().equals(data, mtOff,
					MSG_TYPE_CONFIRM2, 0, 8)) {
				doConfirm2(data, offset, len);
			} else if (platform.getUtils().equals(data, mtOff,
					MSG_TYPE_CONF2ACK, 0, 8)) {
				doConf2ACK(data, offset, len);
			} else if (platform.getUtils().equals(data, mtOff, MSG_TYPE_ERROR,
					0, 8)) {
				doError(data, offset, len);
			} else if (platform.getUtils().equals(data, mtOff,
					MSG_TYPE_ERRORACK, 0, 8)) {
				doErrorACK(data, offset, len);
			} else if (platform.getUtils().equals(data, mtOff,
					MSG_TYPE_GOCLEAR, 0, 8)) {
				doGoClear(data, offset, len);
			} else if (platform.getUtils().equals(data, mtOff,
					MSG_TYPE_CLEARACK, 0, 8)) {
				doClearACK(data, offset, len);
			} else if (platform.getUtils().equals(data, mtOff,
					MSG_TYPE_SASRELAY, 0, 8)) {
				doSASrelay(data, offset, len);
			} else if (platform.getUtils().equals(data, mtOff,
					MSG_TYPE_RELAYACK, 0, 8)) {
				doRelayACK(data, offset, len);
			} else if (platform.getUtils().equals(data, mtOff, MSG_TYPE_PING,
					0, 8)) {
				doPing(data, offset, len);
			} else if (platform.getUtils().equals(data, mtOff,
					MSG_TYPE_PINGACK, 0, 8)) {
				doPingACK(data, offset, len);
			} else {
				String msgType = new String(data, mtOff, 8);
				logWarning("handleIncomingMessage() message with invalid type = '"
						+ msgType + "'");
				logBuffer("handleIncomingMessage(), message with invalid type",
						data, offset, len);
			}
		} catch (Throwable e) {
			logError("Exception in handleIncomingMessage() - " + e.toString());
			e.printStackTrace();
			sessionCompleted(false, ZrtpStrings.TEXT_ZRTP_ERROR);
		}
	}

	/**
	 * Retrieves the current trust status of the connection.
	 * 
	 * @return true iff the connection is trusted.
	 */
	public boolean isTrusted() {
		if (delayedCacheUpdate || farEndZID == null) {
			return false;
		}
		cache.selectEntry(farEndZID);
		return cache.getTrust();
	}

	private void logBuffer(String str, byte[] buf) {
		platform.getLogger().log("ZRTP: " + str);
		if (platform.isVerboseLogging())
			platform.getLogger().log(
					"      len:" + buf.length, buf);
	}

	private void logBuffer(String str, byte[] buf, int offset, int len) {
		platform.getLogger().log("ZRTP: " + str);
		platform.getLogger().log(
				"      len:" + buf.length, buf, offset, len);
	}

	private void logBufferWarning(String str, byte[] buf, int offset, int len) {
		platform.getLogger().logWarning("ZRTP: " + str);
		platform.getLogger().log(
				"      len:" + buf.length, buf, offset, len);
	}

	private void logError(String str) {
		platform.getLogger().logException("ZRTP: " + str);
	}

	private void logString(String str) {
		platform.getLogger().log("ZRTP: " + str);
	}

	private void logWarning(String str) {
		platform.getLogger().logWarning("ZRTP: " + str);
	}

	private void logZrtpMessage(String str, byte[] buf, int offset, int len) {
		StringBuffer sb = new StringBuffer();
		sb.ensureCapacity(len * 2);
		sb.append("ZRTP: " + str);
		int i = 0;
		for (; i < len / 4; i++) {
			sb.append("      ");
			sb.append(platform.getUtils().byteToHexString(buf, offset + i * 4,
					4));
			sb.append("\n");
		}
		sb.append("      "
				+ platform.getUtils().byteToHexString(buf, offset + i * 4,
						len - i * 4));
		platform.getLogger().log(sb.toString());
	}

	public void masqueradedPacketReceived() {
		rtpStack.setMasqueradingActive();
	}

	private void raiseDenialOfServiceWarning(String warning) {
		if ((securityWarningFlags & 1) == 0) {
			// TODO: should we log all warnings? we're logging only the first
			// one for now
			logWarning("Denial of Service security warning: " + warning);
			securityWarningFlags |= 1;
			listener.securityWarning(SECURITY_WARNING_DOS, warning);
		}
	}

	private void raiseSharedSecretCacheMismatchWarning() {
		if ((securityWarningFlags & 2) == 0) {
			securityWarningFlags |= 2;
			listener.securityWarning(SECURITY_WARNING_CACHE_MISMATCH, null);
		}
	}

	/**
	 * Retrieves the trust status of the connection reported by the remote
	 * client.
	 * 
	 * @return true iff the connection is trusted.
	 */
	public boolean remoteTrust() {
		return remoteTrust;
	}

	private synchronized void retranTimerExpired(RetranTimerTask task) {
		if (completed || task != retranTask) {
			return;
		}
		try {
			if (!started) {
				// Shouldn't happen, but just in case
				logString("Hello Timer Expired when not started");
				return;
			}
			if (state == ZRTP_STATE_SENDING_HELLO) {
				// Not had a HelloACK yet, so send another (unless we've reached
				// the limit)
				if (retranCount < T1_MAX_RETRANSMISSIONS) {
					timerInterval *= 2;
					if (timerInterval > T1_MAXIMUM_INTERVAL) {
						timerInterval = T1_MAXIMUM_INTERVAL;
					}
					retranCount++;
					sendHello();
				} else {
					// Sent Max hello messages with no response
					logString("Session failed, received no response to Hello messages");
					sessionCompleted(false,
							ZrtpStrings.TEXT_ZRTP_NO_HELLO_MESSAGE_RECEIVED);
				}
			} else if (initiator) {
				if (retranCount < T2_MAX_RETRANSMISSIONS) {
					timerInterval *= 2;
					if (timerInterval > T2_MAXIMUM_INTERVAL) {
						timerInterval = T2_MAXIMUM_INTERVAL;
					}
					retranCount++;
					if (platform.getLogger().isEnabled()) {
						logString("ZRTP initiator retransmission #"
								+ retranCount + " in state " + getStateText());
					}
					switch (state) {
					case ZRTP_STATE_COMMIT_SENT:
						sendZrtpPacket(msgCommitTX);
						break;
					case ZRTP_STATE_DHPART2_SENT:
						sendZrtpPacket(msgDhPart2TX);
						break;
					case ZRTP_STATE_CONFIRM2_SENT:
						sendZrtpPacket(msgConfirm2TX);
						break;
					// TODO
					/*
					 * case ZRTP_STATE_: sendGoClear(); break; case ZRTP_STATE_:
					 * sendSASrelay(); break;
					 */
					default:
						if (errorCode != 0) {
							sendZrtpPacket(msgErrorTX);
						}
						break;
					}
					retranTask = new RetranTimerTask();
					retranTimer.schedule(retranTask, timerInterval);
				} else {
					// Sent Max number of messages with no response
					logString("Session failed, received no response in state "
							+ getStateText());
					sessionCompletedKO(
							ZrtpStrings.TEXT_ZRTP_NO_RESPONSE_RECEIVED,
							getStateText());
				}
			} else {
				// responder timeout
				long now = System.currentTimeMillis();
				long dif = now - lastPacketArrival;
				if (dif >= RESPONDER_TIMEOUT) {
					logString("Session failed, responder timeout in state "
							+ getStateText());
					sendError(ZRTP_ERROR_PROTOCOL_TIMEOUT);
					sessionCompletedKO(ZrtpStrings.TEXT_ZRTP_RESPONDER_TIMEOUT,
							getStateText());
				} else {
					retranTask = new RetranTimerTask();
					retranTimer.schedule(retranTask, RESPONDER_TIMEOUT - dif);
				}
			}
		} catch (Throwable e) {
			logError("Exception in retranTimerExpired() - " + e.toString());
			e.printStackTrace();
			sessionCompletedKO(ZrtpStrings.TEXT_ZRTP_ERROR);
		}
	}

	/**
	 * Thread run method
	 */
	private void runSession() {
		if (!started) {
			logString("Thread Starting");
			completed = false;
			seqNum = getStartSeqNum();
			rtpStack.setNextZrtpSequenceNumber(getStartSeqNum());
			state = ZRTP_STATE_INACTIVE;
			initiator = false;
			hashMode = HashType.UNDEFINED;
			dhMode = KeyAgreementType.DH3K;
			sasMode = SasType.UNDEFINED;
			farEndZID = null;
			farEndH0 = null;
			farEndClientID = "";
			isLegacyClient = false;
			// farEndH1 = null;
			// farEndH2 = null;
			// farEndH3 = null;
			farEndZID = null;
			dhPart1Msg = null;
			dhPart2Msg = null;
			rxHelloMsg = txHelloMsg = commitMsg = null;
			msgConfirm1TX = msgConfirm2TX = null;
			msgConfirm1RX = msgConfirm2RX = null;
			msgErrorTX = null;

			try {
				// TODO: create after algorithm negotiation
				dhSuite.setAlgorithm(KeyAgreementType.ECDH384);
				// Initialize the retransmission timer interval
				timerInterval = T1_INITIAL_INTERVAL;
				sendHello();
				started = true;
			} catch (Throwable e) {
				logError("Exception sending initial Hello message: "
						+ e.toString());
				e.printStackTrace();
				completed = true;
			}
			while (!completed) {
				synchronized (lock) {
					try {
						lock.wait();
					} catch (Throwable e) {
						logString("Thread Interrupted E:" + e);
					}
				}
			}
			endSession();
			logString("Thread Ending");
		}
	}

	private void scheduleTimerResponderTimeout() {
		lastPacketArrival = System.currentTimeMillis();
		// reusing retransmision timer as responder never really needs to
		// retransmit
		retranTask = new RetranTimerTask();
		retranTimer.schedule(retranTask, RESPONDER_TIMEOUT);
	}

	private void scheduleTimerT2() {
		retranCount = 0;
		timerInterval = T2_INITIAL_INTERVAL;
		retranTask = new RetranTimerTask();
		retranTimer.schedule(retranTask, (long) timerInterval);
	}

	private synchronized void sendCommit() throws IOException {
		if (platform.getLogger().isEnabled()) {
			logString("Sending COMMIT...");
		}
		/*
		 * if(forceToBeInitiator) { // send an HELLO_ACK, to make the other peer
		 * state machine progress
		 * logString("Instance forced to be initiator. Sending first HELLO_ACK"
		 * ); iRtpSender.sendZrtpPacket(mMsgHelloACK); forceToBeInitiator =
		 * false; }
		 */
		if (commitMsg == null) {
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			// Commit always has length 29 words in DH mode (which we always
			// use)
			baos.write(createMessageBase(MSG_TYPE_COMMIT, 29));
			baos.write(hashChain.H2);
			baos.write(localZID);
			byte[] hash = dhMode.hash.getType();
			baos.write(hash); // We only use SHA-256
			baos.write(cipherInUse.getType());
			baos.write(AUTH_TYPE_32); // We only use HMAC-SHA1 32
			baos.write(dhMode.getType());
			baos.write(SasType.B256.getType());
			baos.write(createHvi());
			byte[] commit = baos.toByteArray();
			baos.close();
			commitMsg = addImplicitHMAC(commit, hashChain.H1);
			dhSuite.setAlgorithm(dhMode);
			if (TestSettings.TEST && TestSettings.TEST_ZRTP_WRONG_HMAC_COMMIT) {
				randomGenerator.getBytes(commitMsg, commit.length, 2);
			}
		}
		// Save the contents of COMMIT to be sent
		msgCommitTX = commitMsg;
		sendZrtpPacket(commitMsg);
		scheduleTimerT2();
	}

	private synchronized void sendConf2ACK() {
		sendZrtpPacket(mMsgConf2ACK);
		boolean success = listener.keyExchangeCompleted(txMasterKey,
				txMasterSalt, rxMasterKey, rxMasterSalt, seqNum);
		sessionCompleted(success, null);
	}

	// private synchronized void sendGoClear() throws IOException {
	// //TODO send go Clear not implemented
	// //scheduleTimerT2();
	// }
	//
	// private synchronized void sendClearACK() throws IOException {
	// //TODO send clear ACK not implemented
	// }
	//
	// private synchronized void sendSASrelay() throws IOException {
	// //TODO send SAS relay not implemented
	// //scheduleTimerT2();
	// }
	//
	// private synchronized void sendRelayACK() throws IOException {
	// //TODO send relay ACK not implemented
	// }

	private synchronized void sendConfirm1() throws IOException,
			CryptoException {
		if (platform.getLogger().isEnabled()) {
			logString("Sending Confirm1...");
		}
		if (msgConfirm1TX == null) {
			msgConfirm1TX = createConfirmMsg(true);
			confirm1Timestamp = System.currentTimeMillis();
		}
		sendZrtpPacket(msgConfirm1TX);
		state = ZRTP_STATE_CONFIRM1_SENT;
	}

	// private synchronized void sendPingACK() throws IOException {
	// //TODO send Ping Ack not implemented
	// }

	private synchronized void sendConfirm2() throws IOException,
			CryptoException {
		if (platform.getLogger().isEnabled()) {
			logString("Sending Confirm2...");
		}
		if (msgConfirm2TX == null) {
			msgConfirm2TX = createConfirmMsg(false);
			s0 = null; // we're done with s0, clear as required by ZRTP spec,
						// section 4.6.1
		}
		sendZrtpPacket(msgConfirm2TX);
		state = ZRTP_STATE_CONFIRM2_SENT;
		scheduleTimerT2();
	}

	private synchronized void sendDHPart1() throws IllegalArgumentException,
			ZrtpException {
		if (platform.getLogger().isEnabled()) {
			logString("Sending DHPart1...");
		}
		if (dhPart1Msg == null) {
			dhPart1Msg = createDHPartX(MSG_TYPE_DHPART1);
		}
		if (TestSettings.TEST && TestSettings.TEST_ZRTP_WRONG_HMAC_DHPART1) {
			randomGenerator.getBytes(dhPart1Msg, dhPart1Msg.length - 8, 2);
		}
		// Save the contents of DHPart1 to be sent
		msgDhPart1TX = dhPart1Msg;
		sendZrtpPacket(dhPart1Msg);
	}

	private synchronized void sendDHPart2() throws IllegalArgumentException,
			ZrtpException {
		if (platform.getLogger().isEnabled()) {
			logString("Sending DHPart2...");
		}
		if (dhPart2Msg == null) {
			dhPart2Msg = createDHPartX(MSG_TYPE_DHPART2);
		}
		if (TestSettings.TEST && TestSettings.TEST_ZRTP_WRONG_HMAC_DHPART2) {
			randomGenerator.getBytes(dhPart2Msg, dhPart2Msg.length - 8, 2);
		}
		sendZrtpPacket(dhPart2Msg);
		// Save the contents of DHPart2 that was sent
		msgDhPart2TX = dhPart2Msg;
		scheduleTimerT2();
	}

	private synchronized void sendError(int code) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		baos.write(createMessageBase(MSG_TYPE_ERROR, 4));
		// Only the 2 least significant bytes of error code are of interest
		baos.write(0x00);
		baos.write(0x00);
		baos.write((byte) ((code >>> 8) & 0xFF));
		baos.write((byte) (code & 0xFF));
		byte[] msg = baos.toByteArray();
		baos.close();
		sendZrtpPacket(msg);
		msgErrorTX = msg;
		errorCode = code;
		scheduleTimerT2();
	}

	private synchronized void sendErrorACK() {
		sendZrtpPacket(mMsgErrorACK);
	}

	private synchronized void sendHello() throws IOException {
		if (platform.getLogger().isEnabled()) {
			logString("Sending HELLO...");
		}
		state = ZRTP_STATE_SENDING_HELLO;
		if (TestSettings.TEST && TestSettings.TEST_ZRTP_ZID_COLLISION
				&& farEndZID == null) {
			// do not start sending Hello, but wait other peer's hello
			// in order to answer with the same ZID and trigger the ZID
			// collision
			platform.getLogger().log(
					"Waiting sending HELLO to simulate ZID collision");
			sendPing();
		} else {
			if (txHelloMsg == null) {
				txHelloMsg = createHelloMsg();
			}
			sendZrtpPacket(txHelloMsg);
			// logString("Scheduling next HELLO to be sent in "+iTimerInterval+"ms ...");
		}
		retranTask = new RetranTimerTask();
		retranTimer.schedule(retranTask, (long) timerInterval);
	}

	private synchronized void sendHelloACK() {
		if (platform.getLogger().isEnabled()) {
			logString("Sending HELLOACK...");
		}
		/*
		 * if(forceToBeInitiator && iState != ZRTP_STATE_COMMIT_SENT) { //
		 * nothing to do. Do not send COMMIT message, so the other // peer will
		 * wait before sending COMMITT and we will be Initiator
		 * logString("Sending HELLOACK skipped in state=" + getStateText()); }
		 * else
		 */
		sendZrtpPacket(mMsgHelloACK);
	}

	private synchronized void sendPing() throws IOException {
		if (txPingMsg == null) {
			txPingMsg = createPingMsg();
		}
		sendZrtpPacket(txPingMsg);
	}

	private void sendZrtpPacket(byte[] msg) {
		if (platform.isVerboseLogging()) {
			logZrtpMessage("SEND MSG", msg, 0, msg.length);
		}
		rtpStack.sendZrtpPacket(msg);
	}

	private void sessionCompleted(boolean success, String msg) {
		if (!completed) {
			retranTimer.cancel();
			retranTask = null;
			completed = true;
			logString("sessionCompleted(" + success + ")");
			listener.sessionNegotiationCompleted(success, msg);
			synchronized (lock) {
				lock.notify();
			}
		}
	}

	private void sessionCompletedKO(String errorMessage) {
		sessionCompletedKO(errorMessage, null);
	}

	private void sessionCompletedKO(String errorMessage, String details) {
		String msg = errorMessage;
		if (details != null)
			msg += " (" + details + ")";
		sessionCompleted(false, msg);
	}

	private void sessionCompletedOK() {
		sessionCompleted(true, null);
	}

	public void setMasqueradingOn() {
		rtpStack.setMasqueradingDual();
	}

	/**
	 * Sets the phone number of other party for use in addressbook lookup during
	 * verification
	 * 
	 * @param number
	 *            Phone number of the other party
	 */
	public void setPhoneNumber(String number) {
		phoneNumber = number;
		System.out.println(phoneNumber);
	}

	public void setProtocolManager(ZrtpListener zrtpListener) {
		listener = zrtpListener;
	}

	public void setRtpStack(RtpStack stack) {
		rtpStack = stack;
	}

	/**
	 * Hash of the Hello message to be received. This hash is sent by the other
	 * end as part of the SDP for further verification.
	 * 
	 * @param version
	 *            ZRTP version of the hash
	 * @param helloHash
	 *            Hello hash received as part of SDP in SIP
	 */
	public void setSdpHelloHash(String version, String helloHash) {
		if (!version.startsWith(VERSION_PREFIX)) {
			logWarning("Different version number: '" + version + "' Ours: '"
					+ VERSION_PREFIX + "' (" + VERSION + ")");
		}
		sdpHelloHashReceived = helloHash;
	}

	public void startSession() {
		Thread t = new Thread(new Runnable() {
			public void run() {
				runSession();
			}
		}, "ZRTP-" + "ZRTP-" + (counter++));
		t.start();
	}

	/**
	 * Stop ZRTP Session
	 */
	public void stopSession() {
		endSession();
		synchronized (lock) {
			lock.notify();
		}
	}

	public void successfulSrtpUnprotect() {
		logString("Accepting successful SRTP unprotect instead of Conf2ACK, faking Conf2ACK");
		doConf2ACK(null, 0, 0);
	}

	/**
	 * Notifies the ZRTP protocol that the user has chosen to trust the
	 * connection. SAS verified flags is set to true and shared secrets are
	 * stored in the cache (they should already be in the cache unless they were
	 * removed by untrust() or delayed because of cache mismatch).
	 */
	public void trust() {
		cache.updateEntry(cacheExpiryTime(), true, newRS, keepRS2, phoneNumber);
		delayedCacheUpdate = false;
	}

	/**
	 * Notifies the ZRTP protocol that the user has revoked their trust in the
	 * connection. SAS verified flags is set to false and shared secrets with
	 * the remote end are removed from the cache.
	 */
	public void untrust() {
		cache.updateEntry(cacheExpiryTime(), false, newRS, keepRS2, null);
		delayedCacheUpdate = true;
	}

	private boolean validateCommitMessage(byte[] data, int offset) {
		// length == 116 verified in doCommit
		boolean msgValid = true;

		logString("COMMIT MESSAGES RECEIVED");
		logString("hash type - " + (new String(data, offset + 56, 4)));
		logString("cipher type - " + (new String(data, offset + 60, 4)));
		logString("auth type - " + (new String(data, offset + 64, 4)));
		logString("key type - " + (new String(data, offset + 68, 4)));
		logString("sas type - " + (new String(data, offset + 72, 4)));
		if (!platform.getUtils().equals(farEndZID, 0, data, offset + 44, 12)) {
			msgValid = false;
			logString("validateCommitMessage, Commit contains invalid ZID");
		} else if (!platform.getUtils().equals(HashType.SHA256.getType(), 0,
				data, offset + 56, 4)
				&& !platform.getUtils().equals(HashType.SHA384.getType(), 0,
						data, offset + 56, 4)) {
			msgValid = false;
			logString("validateCommitMessage, Found invalid hash type - "
					+ (new String(data, offset + 56, 4)));
		} else if (!platform.getUtils().equals(CipherType.AES1.getType(), 0,
				data, offset + 60, 4)
				&& !platform.getUtils().equals(CipherType.AES3.getType(), 0,
						data, offset + 60, 4)) {
			msgValid = false;
			logString("validateCommitMessage, Found invalid cipher type - "
					+ (new String(data, offset + 60, 4)));
		} else if (!platform.getUtils().equals(AUTH_TYPE_32, 0, data,
				offset + 64, 4)) {
			msgValid = false;
			logString("validateCommitMessage, Found invalid auth type - "
					+ (new String(data, offset + 64, 4)));
		} else if (!platform.getUtils().equals(
				KeyAgreementType.ECDH384.getType(), 0, data, offset + 68, 4)
				&& !platform.getUtils().equals(
						KeyAgreementType.ECDH256.getType(), 0, data,
						offset + 68, 4)
				&& !platform.getUtils().equals(KeyAgreementType.DH3K.getType(),
						0, data, offset + 68, 4)) {
			msgValid = false;
			logString("validateCommitMessage, Found invalid key type - "
					+ (new String(data, offset + 68, 4)));
		} else if (!platform.getUtils().equals(SasType.B32.getType(), 0, data,
				offset + 72, 4)
				&& !platform.getUtils().equals(SasType.B256.getType(), 0, data,
						offset + 72, 4)) {
			msgValid = false;
			logString("validateCommitMessage, Found invalid sas type - "
					+ (new String(data, offset + 72, 4)));
		}

		return (msgValid);
	}

	/**
	 * Verify whether the contents of the Hello message received has not been
	 * altered, by matching with the SHA256 hash received in SDP exchange.
	 * 
	 * @param helloMsg
	 *            Contents of the Hello message received
	 * @return True if the Hello message is verified, false if not.
	 */
	private boolean verifyHelloMessage(byte[] helloMsg) {
		if (sdpHelloHashReceived != null) {
			String hash = calculateSHA256Hash(helloMsg, 0, helloMsg.length);
			boolean hashesMatched = hash.toUpperCase().equals(
					sdpHelloHashReceived.toUpperCase());
			if (platform.getLogger().isEnabled()) {
				if (hashesMatched) {
					logString("verifyHelloMessage() Hello hash verified OK.");
				} else {
					logString("verifyHelloMessage() Hello hash does NOT match  hash= '"
							+ hash
							+ "' expected (SDP) = '"
							+ sdpHelloHashReceived + "'");
				}
			}
			return hashesMatched;
		} else {
			return true;
		}
	}

	private void writeSharedSecretID(byte[] dhPart, int off, byte[] msg,
			byte[] secret) {
		if (secret == null) {
			randomGenerator.getBytes(dhPart, off, 8);
		} else {
			byte[] mac = createSHAHMAC(msg, 0, msg.length, secret);
			System.arraycopy(mac, 0, dhPart, off, 8);
		}
	}
}