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

import zorg.platform.EncryptorSuite;
import zorg.platform.HMAC;
import zorg.platform.LongSortedVector;
import zorg.platform.Platform;
import zorg.platform.RtpPacket;

/**
 * Implementation of SRTP for PrivateGSM Note this is not a full implementation
 * and provides no support for SRTCP
 */
public class SRTP {

	public static final int SESSION_OK = 0;
	public static final int SESSION_ERROR_ALREADY_ACTIVE = -3;
	public static final int SESSION_ERROR_MASTER_SALT_UDNEFINED = -2;
	public static final int SESSION_ERROR_MASTER_KEY_UDNEFINED = -1;
	public static final int SESSION_ERROR_KEY_DERIVATION_FAILED = -99;
	public static final int SESSION_ERROR_RESOURCE_CREATION_PROBLEM = -98;

	public static final int UNPROTECT_OK = 0;
	public static final int UNPROTECT_SESSION_NOT_STARTED = -1;
	public static final int UNPROTECT_ERROR_DECRYPTING = -2;
	public static final int UNPROTECT_INVALID_PACKET = -3;
	public static final int UNPROTECT_NULL_PACKET = -4;
	public static final int UNPROTECT_REPLAYED_PACKET = -5;

	private long rollOverCounter = 0; // RollOver Counter (for send packets)
	private long rxRoc = 0; // RollOver Counter for receive packets
	private int kdr = 48; // Key Derivation Rate (2^iKDR packets before using
							// new keys)
	private int firstRtpSeq; // Sequence number of 1st send packet in session
								// (used in session key generation)
	private int rxSeq; // Sequence number of last packet received in session
						// (needed by decrypt key generation)
	private boolean receivedFirst; // True if 1st packet of a session has been
									// received (needed by decrypt key
									// generation)
	private int previousSSRC;

	private byte[] txSessEncKey; // Session key for encryption, Tx Session
	private byte[] txSessAuthKey; // Session key for authentication, Tx Session
	private byte[] txSessSaltKey; // Session salt key, Tx Session
	private byte[] txMasterKey; // Master key used to create Tx session keys
	private byte[] txMasterSalt; // Master salt used to create Tx session keys
	private byte[] txIV; // IV Array used for TX
	private byte[] rxSessEncKey; // Session key for encryption, Rx Session
	private byte[] rxSessAuthKey; // Session key for authentication, Rx Session
	private byte[] rxSessSaltKey; // Session salt key, Rx Session
	private byte[] rxMasterKey; // Master key used to create Rx session keys
	private byte[] rxMasterSalt; // Master salt used to create Rx session keys
	private byte[] rxIV; // IV Array used for RX

	private EncryptorSuite txEncryptorSuite;
	private byte[] txEncOut;
	private HMAC txHMAC;
	private byte[] txRocAuthArray; // Used during authentication of Tx packets
	private byte[] txAuthHMACArray; // Used by Tx Authentication for HMAC result
	private byte[] txAuthResultArray; // Used by Tx Authentication for final
										// result

	private EncryptorSuite rxEncryptorSuite;
	private byte[] rxEncOut;
	private HMAC rxHMAC;
	private byte[] rxRocAuthArray; // Used during authentication of Rx packets
	private byte[] rxAuthHMACArray; // Used by Rx Authentication for HMAC result
	private byte[] rxAuthResultArray; // Used by Rx Authentication for final
										// result
	private byte[] initVector; // Initialisation Vector for AES encryption

	private LongSortedVector replayWindow; // Stores received sequence numbers
											// to allow replay protection checks

	public static final int MASTER_KEY_SIZE_32_BYTES = 32; // PrivateGSM Tech
															// Spec, 5.4.3 -
															// only support 256
															// bit keys
	public static final int MASTER_KEY_SIZE_16_BYTES = 16; // Also allow 16 byte
															// keys
	public static final int MASTER_SALT_SIZE_BYTES = 14; // ZRTP Spec, 4.5.3 -
															// always use 112
															// bit salt
	public static final int HMAC_AUTH_SIZE_BYTES = 4; // ZRTP Spec 4.5.3 -
														// always use 32 bit
														// HMAC for
														// Authentication
	private static final int SRTP_WINDOW_SIZE = 64; // rfc3711, window size for
													// replay protection checks

	// Used to log detailed and extensive traces
	private boolean VERBOSE = false;
	private boolean SUPER_VERBOSE = false;
	private final Platform platform;

	/**
	 * Constructor
	 */
	public SRTP(Platform platform) {
		this.platform = platform;
		VERBOSE = VERBOSE || SUPER_VERBOSE;
		txMasterKey = txMasterSalt = rxMasterKey = rxMasterSalt = null;
		txSessEncKey = null;
		txSessAuthKey = null;
		txSessSaltKey = null;
		rxSessEncKey = null;
		rxSessAuthKey = null;
		rxSessSaltKey = null;
		firstRtpSeq = 1;
		rollOverCounter = 0;
		initVector = new byte[16];
		platform.getUtils().zero(initVector);
		txRocAuthArray = new byte[4]; // ROC Array used in Tx Auth always 4
										// bytes
		txAuthHMACArray = new byte[20]; // HMAC result is always 20 bytes
		txAuthResultArray = new byte[HMAC_AUTH_SIZE_BYTES];
		rxRocAuthArray = new byte[4]; // ROC Array used in Tx Auth always 4
										// bytes
		rxAuthHMACArray = new byte[20]; // HMAC result is always 20 bytes
		rxAuthResultArray = new byte[HMAC_AUTH_SIZE_BYTES];
	}

	private byte[] encryptIV(byte[] iv, boolean isTransmitting)
			throws CryptoException {
		if (isTransmitting) {
			txEncryptorSuite.encrypt(iv, txEncOut);
			return txEncOut;
		} else {
			rxEncryptorSuite.encrypt(iv, rxEncOut);
			return rxEncOut;
		}
	}

	/**
	 * Ends the currently active session (no effect if no session is started)
	 */
	public void endSession() {
		if (replayWindow != null) {
			replayWindow.removeAllElements();
		}
		replayWindow = null;
		txEncryptorSuite = rxEncryptorSuite = null;
		txIV = rxIV = null;
		txEncOut = rxEncOut = null;
		txHMAC = rxHMAC = null;
		txSessEncKey = null;
		txSessAuthKey = null;
		txSessSaltKey = null;
		rxSessEncKey = null;
		rxSessAuthKey = null;
		rxSessSaltKey = null;
		firstRtpSeq = 1;
		rollOverCounter = 0;
	}

	private byte[] getAuthentication(RtpPacket packet, long roc,
			boolean isTransmitting) throws CryptoException {
		// returns an authentication array which may be added to an RTP payload
		// (when sending)
		// or compared to auth array in a received RTP Payload
		// Authentication is based on entire RTP Packet with 4 byte ROC appended
		//
		long tempRoc = roc >>> 16;
		if (isTransmitting) {
			for (int i = 3; i >= 0; --i) {
				txRocAuthArray[3 - i] = (byte) ((tempRoc >>> (i << 3)) & 0xff);
			}
			txHMAC.reset();
			txHMAC.update(packet.getPacket(), 0, packet.getLength());
			txHMAC.update(txRocAuthArray);
			txHMAC.getMAC(txAuthHMACArray, 0);
			// auth created above will be 20 bytes, but we use fixed 32 bit auth
			// rfc3711, section 4.2.1 states use of left most n bits
			System.arraycopy(txAuthHMACArray, 0, txAuthResultArray, 0, 4);
			return (txAuthResultArray);
		} else {
			for (int i = 3; i >= 0; --i) {
				rxRocAuthArray[3 - i] = (byte) ((tempRoc >>> (i << 3)) & 0xff);
			}
			rxHMAC.reset();
			rxHMAC.update(packet.getPacket(), 0, packet.getLength());
			rxHMAC.update(rxRocAuthArray);
			rxHMAC.getMAC(rxAuthHMACArray, 0);
			// auth created above will be 20 bytes, but we use fixed 32 bit auth
			// rfc3711, section 4.2.1 states use of left most n bits
			System.arraycopy(rxAuthHMACArray, 0, rxAuthResultArray, 0, 4);
			return (rxAuthResultArray);
		}
	}

	public int getFirstRtpSeqNum() {
		return firstRtpSeq;
	}

	/**
	 * Get KDR (Key Definition Rate)
	 * 
	 * @return KDR
	 */
	public int getKDR() {
		return kdr;
	}

	/**
	 * Gets the Receive master key
	 * 
	 * @return master key
	 */
	public byte[] getRxMasterKey() {
		return platform.getUtils().copy(rxMasterKey);
	}

	/**
	 * Get the Receive Master Salt
	 * 
	 * @return master salt string
	 */
	public byte[] getRxMasterSalt() {
		return platform.getUtils().copy(rxMasterSalt);
	}

	public byte[] getRxSessionAuthenticationKey() {
		return (platform.getUtils().copy(rxSessAuthKey));
	}

	public byte[] getRxSessionEncryptionKey() {
		return (platform.getUtils().copy(rxSessEncKey));
	}

	public byte[] getRxSessionSaltKey() {
		return (platform.getUtils().copy(rxSessSaltKey));
	}

	/**
	 * Gets the Transmit master key
	 * 
	 * @return master key
	 */
	public byte[] getTxMasterKey() {
		return platform.getUtils().copy(txMasterKey);
	}

	/**
	 * Get the Transmit Master Salt
	 * 
	 * @return master salt string
	 */
	public byte[] getTxMasterSalt() {
		return platform.getUtils().copy(txMasterSalt);
	}

	public byte[] getTxSessionAuthenticationKey() {
		return (platform.getUtils().copy(txSessAuthKey));
	}

	public byte[] getTxSessionEncryptionKey() {
		return (platform.getUtils().copy(txSessEncKey));
	}

	public byte[] getTxSessionSaltKey() {
		return (platform.getUtils().copy(txSessSaltKey));
	}

	private void incrementIV(byte[] iv) {
		if (iv[15] != 0xFF) {
			iv[15] += 1;
		} else if (iv[14] != 0xFF) {
			iv[15] = 0;
			iv[14] += 1;
		} else if (iv[13] != 0xFF) {
			iv[15] = 0;
			iv[14] = 0;
			iv[13] += 1;
		} else if (iv[12] != 0xFF) {
			iv[15] = 0;
			iv[14] = 0;
			iv[13] = 0;
			iv[12] += 1;
		} else {
			iv[15] = 0;
			iv[14] = 0;
			iv[13] = 0;
			iv[12] = 0;
		}
	}

	private void initialiseIV(byte[] iv, long ssrc, int seq, long roc,
			byte[] aSessSaltKey) {
		// First calculate initial IV for encryption
		// from rfc3711:
		// IV = (k_s * 2^16) XOR (SSRC * 2^64) XOR (i * 2^16)
		// k_s is session salt key
		// SSRC from RTP Packet
		// i is SRTP SEQ num (i.e. iROC+seq)
		platform.getUtils().zero(iv);
		System.arraycopy(aSessSaltKey, 0, iv, 0, 14);
		// IV now contains k_s * 2^16, since k_s is 14 bytes long
		// Now xor with SSRC*2^64 - aSsrc is a long only to make it unsigned,
		// only 4 LSB of interest
		for (int i = 4; i < 8; ++i) {
			byte b = (byte) ((ssrc >>> ((7 - i) << 3)) & 0xFF);
			iv[i] = (byte) (b ^ iv[i]);
		}
		// initVector now contains (k_s*2^16) XOR (SSRC*2^64)
		iv[13] = (byte) ((seq & 0xff) ^ iv[13]);
		iv[12] = (byte) (((seq >>> 8) & 0xff) ^ iv[12]);
		long tempROC = roc >>> 16; // Only a long to make it unsigned, only 4
									// bytes of interest
		for (int i = 11; i >= 8; --i) {
			iv[i] ^= (byte) (tempROC & 0xFF);
			tempROC = tempROC >>> 8;
		}
		if (VERBOSE) {
			log("initialiseIV() - " + platform.getUtils().byteToHexString(iv));
		}
	}

	private boolean isReplayedPacket(long aSeq) {
		// Replay Protection
		// If we've seen this packet before, it must be discarded
		// Packets that lag latest by more than window size are also discarded
		// see rfc3711, 3.2.3
		// Returns true if packet should be discarded
		long curSeq = rxRoc + rxSeq;
		if (aSeq < (curSeq - SRTP_WINDOW_SIZE)) {
			platform.getLogger().logWarning(
					"SRTP replay protection: seq #" + aSeq + ", rxRoc=" + rxRoc
							+ ", rxSeq=" + rxSeq + ", curSeq=" + curSeq
							+ ", WINDOW_SZIE=" + SRTP_WINDOW_SIZE);
			return true;
		}
		Long newElement = new Long(aSeq);
		int numElements = replayWindow.size();
		int found = replayWindow.find(newElement);
		if (found < 0) {
			// Not in the array, add it
			replayWindow.addElement(newElement);
			if (aSeq > curSeq) {
				// New packet is later than any we've seen
				// Readjust window contents to delete those older than window
				// size
				long oldestSeq = aSeq - SRTP_WINDOW_SIZE;
				int numToRemove = 0;
				for (int i = 0; i < numElements; i++) {
					Long l = (replayWindow.getAt(i));
					long seq = l.longValue();
					if (seq < oldestSeq) {
						numToRemove++;
					} else {
						// Since its a sorted array, once we've seen a sequence
						// number inside
						// the window, we can stop looking
						i = numElements;
					}
				}
				while (numToRemove > 0) {
					replayWindow.removeElementAt(0);
					numToRemove--;
				}
			}
		} else {
			// Its a replayed packet
			platform.getLogger().logWarning(
					"SRTP replay protection: found=" + found);
			platform.getLogger().logWarning(
					"SRTP replay protection: seq #" + aSeq + ", rxRoc=" + rxRoc
							+ ", rxSeq=" + rxSeq + ", curSeq=" + curSeq
							+ ", WINDOW_SZIE=" + SRTP_WINDOW_SIZE);
			return true;
		}

		return false;
	}

	private void log(String aMsg) {
		platform.getLogger().log("SRTP: " + aMsg);
	}

	private void logBuffer(String aMsg, byte[] aBuf) {
		platform.getLogger().log("SRTP: " + aMsg, aBuf);
	}

	private void logDebug(String msg) {
		if (platform.isVerboseLogging())
			log(msg);
	}

	private void logError(String aMsg) {
		platform.getLogger().logException("SRTP: " + aMsg);
	}

	private void logWarning(String aMsg) {
		platform.getLogger().logWarning("SRTP: " + aMsg);
	}

	private byte[] prf_128(byte[] key, byte[] x, int outLen) {
		// Generate key for session by encrypting aX with aKey
		// using IV = aX*2^16
		// see rfc3711, 4.3.3
		//
		// Assumes here that aX is 14 bytes long, which is safe in this
		// implementation
		// because we operate with a fixed 112 bit master salt (as indicated in
		// zrtp spec)
		// For a more general srtp impl, would need to check size and pad
		// accordingly
		//
		byte[] IV = new byte[16];
		platform.getUtils().zero(IV);
		System.arraycopy(x, 0, IV, 0, x.length);
		byte[] outArray = null;
		try {
			// AESKey aesKey = new AESKey(aKey);
			// AESEncryptorEngine engine = new AESEncryptorEngine(aesKey);

			EncryptorSuite encSuite = platform.getCrypto()
					.createEncryptorSuite(key, initVector);

			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			int maxLoops = 1 + ((outLen - 1) >>> 4);
			for (int i = 0; i < maxLoops; ++i) {
				byte[] outBlock = encSuite.encryptIV_for_prf(IV);
				if (VERBOSE) {
					log("prf_128 IV = "
							+ platform.getUtils().byteToHexString(IV));
					log("prf_128 loop count = " + i);
					log("prf_128 outBlock = "
							+ platform.getUtils().byteToHexString(outBlock));
				}
				baos.write(outBlock);
				incrementIV(IV);
			}
			outArray = baos.toByteArray();
			baos.close();
		} catch (Throwable e) {
			log("ENCRYPT ERROR 1: " + e.getMessage());
			e.printStackTrace();
			return null;
		}
		// outArray size will be a multiple of 16 bytes
		// Need to trim to required size
		byte[] resultArray = new byte[outLen];
		System.arraycopy(outArray, 0, resultArray, 0, outLen);
		return resultArray;
	}

	/**
	 * Protects an RTP Packet by encrypting payload and adds any additional SRTP
	 * trailer information
	 * 
	 * @param packet
	 *            RTP Packet to be protected
	 * @return New RTP Packet with encrypted payload, or null if an error
	 *         occurred If encryption is disabled, returned packet is identical
	 *         to supplied packet
	 */
	public RtpPacket protect(RtpPacket packet) {
		if (txSessEncKey == null) {
			log("protect() called out of session");
			return null;
		}
		if (packet == null) {
			log("protect() called with null RTP packet");
			return null;
		}

		int seqNum = packet.getSequenceNumber();
		if (seqNum == 0) {
			// wrapped round
			rollOverCounter += 0x10000L;
		}

		RtpPacket retPacket = null;

		if (!transformPayload(packet, rollOverCounter, seqNum, txSessSaltKey,
				true)) {
			log("protect() transformPayload error, encryption failed");
			return null;
		}

		// Add authentication which is over whole rtp packet concatenated with
		// 48 bit ROC
		byte[] auth = null;
		try {
			auth = getAuthentication(packet, rollOverCounter, true); // iTxSessAuthKey);
			if (VERBOSE) {
				log("protect() Adding HMAC:");
				logBuffer("auth:", auth);
			}
		} catch (Throwable e) {
			logError("protect() Authentication error EX: " + e);
			e.printStackTrace();
			return null;
		}
		// aPacket should have HMAC_AUTH_SIZE_BYTES bytes pre-allocated for the
		// auth-code
		// assert(aPacket.getPacket().length >= aPacket.getLength() +
		// HMAC_AUTH_SIZE_BYTES);
		System.arraycopy(auth, 0, packet.getPacket(), packet.getLength(),
				HMAC_AUTH_SIZE_BYTES);
		packet.setPayloadLength(packet.getPayloadLength()
				+ HMAC_AUTH_SIZE_BYTES);
		retPacket = packet;
		if (SUPER_VERBOSE) {
			logBuffer("protect() After adding HMAC: ", retPacket.getPacket());
		}
		return retPacket;
	}

	private boolean rxSessionKeyDerivation() {
		boolean res = true;
		// Need to produce 3 keys (session encryption, session authentication
		// and session salt)
		// All based on same value of r, above, but with labels of 0x00, 0x01 &
		// 0x02
		// See comments in txSessionKeyDerivation
		if (VERBOSE) {
			platform.getLogger().log("SRTP RX session key derivation");
		}
		byte label = 0x00;
		while (label <= 0x02) {
			if (VERBOSE) {
				logDebug("+++ label = " + label);
			}
			// Can cheat here, since only one byte of key_id affects the XOR
			// (and iRxROC is always initialised to 0 at receipt of 1st packet)
			byte[] x = platform.getUtils().copy(rxMasterSalt);
			x[7] ^= label;
			if (VERBOSE) {
				logDebug("+++ x = " + platform.getUtils().byteToHexString(x));
			}
			if (label == 0) {
				rxSessEncKey = prf_128(rxMasterKey, x, rxMasterKey.length);
				if (rxSessEncKey == null) {
					res = false;
					break;
				} else {
					if (VERBOSE) {
						logDebug("+++ enc key = "
								+ platform.getUtils().byteToHexString(
										rxSessEncKey));
					}
				}
			} else if (label == 1) {
				rxSessAuthKey = prf_128(rxMasterKey, x, 20);
				if (rxSessAuthKey == null) {
					res = false;
					break;
				} else {
					if (VERBOSE) {
						logDebug("+++ auth key = "
								+ platform.getUtils().byteToHexString(
										rxSessAuthKey));
					}
				}
			} else {
				rxSessSaltKey = prf_128(rxMasterKey, x, 14);
				if (rxSessSaltKey == null) {
					res = false;
					break;
				} else {
					if (VERBOSE) {
						logDebug("+++ salt key = "
								+ platform.getUtils().byteToHexString(
										rxSessSaltKey));
					}
				}
			}
			label++;
		}
		if (res) {
			// Create encryptor engine for rx session
			try {
				rxEncryptorSuite = platform.getCrypto().createEncryptorSuite(
						rxSessEncKey, initVector);
				rxHMAC = platform.getCrypto().createHMACSHA1(rxSessAuthKey);
			} catch (Throwable e) {
				logError("rxSessionKeyDerivation failed to create Tx encryptor EX: "
						+ e);
				e.printStackTrace();
				res = false;
			}
		}
		if (!res) {
			// tidy up if failed
			logWarning("rxSessionKeyDerivation FAILED");
			rxSessEncKey = null;
			rxSessAuthKey = null;
			rxSessSaltKey = null;
		}
		if (VERBOSE) {
			logDebug("+++ ----------");
		}
		return res;
	}

	/**
	 * Sets the 1st RTP Sequence number to be used in the next session. Needed
	 * by SRTP session key generation. If not set, a sequence number of 1 is
	 * used. Setting the sequence number after a session is started has no
	 * effect.
	 * 
	 * @param seq
	 *            sequence number of 1st rtp packet
	 */
	public void setFirstRtpSeqNum(int seq) {
		if (txSessEncKey == null) {
			firstRtpSeq = seq;
		}
	}

	/**
	 * Set KDR (Key Definition Rate)
	 * 
	 * @param keyDefinitionRate
	 *            New key definition rate is 2^aKDR, and maximum is 64 (2^64)
	 * @return true if successfully set, false for invalid KDR values
	 */
	public boolean setKDR(int keyDefinitionRate) {
		boolean res = true;
		if ((keyDefinitionRate > 64) || (keyDefinitionRate <= 0)) {
			log("setKDR() - invalid parameter " + keyDefinitionRate);
			res = false;
		} else {
			kdr = keyDefinitionRate;
		}
		return res;
	}

	public void setROC(long aROC) {
		if (TestSettings.TEST) {
			rollOverCounter = aROC & 0xFFFFFFFFFFFF0000L;
		}
	}

	//
	// Methods used for unit testing below here
	//

	/**
	 * Sets the Master Key to be used for generating the Receive session keys
	 * (only 256 bit keys supported - see PrivateGSM Tech Spec, 5.4.3)
	 * 
	 * @param key
	 *            Master Key string
	 * @return true if successfully set, false otherwise (invalid key length)
	 */
	public boolean setRxMasterKey(byte[] key) {
		boolean res = false;
		if ((key.length == MASTER_KEY_SIZE_32_BYTES)
				|| (key.length == MASTER_KEY_SIZE_16_BYTES)) {
			rxMasterKey = null;
			rxMasterKey = platform.getUtils().copy(key);
			res = true;
			logDebug("setRxMasterKey "
					+ platform.getUtils().byteToHexString(rxMasterKey));
		} else {
			logError("Wrong length iRxMasterKey: " + key.length);
		}
		return res;
	}

	/**
	 * Sets the Master Salt to be used for generating the receive session keys
	 * (only supports salt size 112 bits for zrtp - see zrtp spec section 4.5.3)
	 * 
	 * @param salt
	 *            Master Salt string
	 * @return true if set, false otherwise (invalid length string)
	 */
	public boolean setRxMasterSalt(byte[] salt) {
		boolean res = false;
		if (salt.length == MASTER_SALT_SIZE_BYTES) {
			rxMasterSalt = null;
			rxMasterSalt = platform.getUtils().copy(salt);
			res = true;
			logDebug("setRxMasterSalt "
					+ platform.getUtils().byteToHexString(rxMasterSalt));
		} else {
			logError("Wrong length for iRxMasterSalt: " + salt.length
					+ " expected " + MASTER_SALT_SIZE_BYTES + " bytes");
		}
		return res;
	}

	/**
	 * Sets the Master Key to be used for generating the Transmit session keys
	 * (only 256 bit keys supported - see PrivateGSM Tech Spec, 5.4.3)
	 * 
	 * @param key
	 *            Master Key string
	 * @return true if successfully set, false otherwise (invalid key length)
	 */
	public boolean setTxMasterKey(byte[] key) {
		boolean res = false;
		if ((key.length == MASTER_KEY_SIZE_32_BYTES)
				|| (key.length == MASTER_KEY_SIZE_16_BYTES)) {
			txMasterKey = null;
			txMasterKey = platform.getUtils().copy(key);
			res = true;
			logDebug("setTxMasterKey "
					+ platform.getUtils().byteToHexString(txMasterKey));
		} else {
			logError("Wrong length iTxMasterKey: " + key.length);
		}
		return res;
	}

	/**
	 * Sets the Master Salt to be used for generating the transmit session keys
	 * (only supports salt size 112 bits for zrtp - see zrtp spec section 4.5.3)
	 * 
	 * @param salt
	 *            Master Salt string
	 * @return true if set, false otherwise (invalid length string)
	 */
	public boolean setTxMasterSalt(byte[] salt) {
		boolean res = false;
		if (salt.length == MASTER_SALT_SIZE_BYTES) {
			txMasterSalt = null;
			txMasterSalt = platform.getUtils().copy(salt);
			res = true;
			logDebug("setTxMasterSalt "
					+ platform.getUtils().byteToHexString(txMasterSalt));
		} else {
			logError("Wrong length for iTxMasterSalt: " + salt.length
					+ " expected " + MASTER_SALT_SIZE_BYTES + " bytes");
		}
		return res;
	}

	/**
	 * Starts a new SRTP Session, using the preset master key and salt to
	 * generate the session keys
	 * 
	 * @return error code
	 */
	public int startNewSession() {
		if (txSessEncKey != null)
			return SESSION_ERROR_ALREADY_ACTIVE;
		if ((txMasterSalt == null) || (rxMasterSalt == null))
			return SESSION_ERROR_MASTER_SALT_UDNEFINED;
		if ((txMasterKey == null) || (rxMasterKey == null))
			return SESSION_ERROR_MASTER_SALT_UDNEFINED;
		if (!txSessionKeyDerivation()) {
			log("startNewSession txSessionKeyDerivation failed");
			return SESSION_ERROR_KEY_DERIVATION_FAILED;
		}
		// Create encryptor components for tx session
		try {
			// and the HMAC components
			txEncryptorSuite = platform.getCrypto().createEncryptorSuite(
					txSessEncKey, initVector);
			txHMAC = platform.getCrypto().createHMACSHA1(txSessAuthKey);
		} catch (Throwable e) {
			log("startNewSession failed to create Tx encryptor");
			return SESSION_ERROR_RESOURCE_CREATION_PROBLEM;
		}
		replayWindow = platform.getUtils().createSortedVector();
		receivedFirst = false;
		rollOverCounter = 0;
		rxRoc = 0;
		txIV = new byte[16]; // Always uses a 128 bit IV
		rxIV = new byte[16];
		txEncOut = new byte[16];
		rxEncOut = new byte[16];
		return SESSION_OK;
	}

	public boolean testEncryption() {
		// Uses test data in rfc3711 to test encryption
		boolean ret = true;
		rollOverCounter = 0L;
		byte[] sessKey = { (byte) 0x2B, (byte) 0x7E, (byte) 0x15, (byte) 0x16,
				(byte) 0x28, (byte) 0xAE, (byte) 0xD2, (byte) 0xA6,
				(byte) 0xAB, (byte) 0xF7, (byte) 0x15, (byte) 0x88,
				(byte) 0x09, (byte) 0xCF, (byte) 0x4F, (byte) 0x3C };
		byte[] sessSalt = { (byte) 0xF0, (byte) 0xF1, (byte) 0xF2, (byte) 0xF3,
				(byte) 0xF4, (byte) 0xF5, (byte) 0xF6, (byte) 0xF7,
				(byte) 0xF8, (byte) 0xF9, (byte) 0xFA, (byte) 0xFB,
				(byte) 0xFC, (byte) 0xFD };

		byte[] IV = new byte[16];
		initialiseIV(IV, 0L, 0, 0L, sessSalt);
		byte[] outArray = null;
		try {
			// AESKey key = new AESKey(sessKey);
			// AESEncryptorEngine engine = new AESEncryptorEngine(key);
			EncryptorSuite encSuite = platform.getCrypto()
					.createEncryptorSuite(sessKey, initVector);
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			for (int i = 0; i < 3; ++i) {
				logBuffer("testEncryption, IV - ", IV);
				byte[] encrypted = encSuite.encryptIV_for_prf(IV);
				logBuffer("testEncryption, encrypted block - ", encrypted);
				baos.write(encrypted);
				incrementIV(IV);
			}
			outArray = baos.toByteArray();
			baos.close();
			logBuffer("testEncryption, outArray - ", outArray);
		} catch (Throwable e) {
			log("testEncryption, Exception thrown");
			ret = false;
		}
		String outString = platform.getUtils().byteToHexString(outArray);
		String expectedOutput = "E03EAD0935C95E80E166B16DD92B4EB4D23513162B02D0F72A43A2FE4A5F97AB41E95B3BB0A2E8DD477901E4FCA894C0";
		if (!outString.equalsIgnoreCase(expectedOutput)) {
			ret = false;
		}
		return ret;
	}

	public boolean testReplayCheckVector() {
		boolean ret = true;
		if (TestSettings.TEST) {
			LongSortedVector v = platform.getUtils().createSortedVector();
			v.addElement(new Long(5L));
			v.addElement(new Long(10L));
			v.addElement(new Long(1L));
			// Order in vector should be 1, 5, 10
			Long l = (v.getAt(0));
			if (l.longValue() != 1L) {
				ret = false;
			} else {
				l = (v.getAt(2));
				if (l.longValue() != 10L) {
					ret = false;
				}
			}
		}
		return ret;
	}

	public boolean testReplayWindow() {
		boolean ret = true;
		if (TestSettings.TEST) {
			replayWindow = platform.getUtils().createSortedVector();
			rxRoc = 0L;
			receivedFirst = false;
			long seq = 1L;
			while (seq <= SRTP_WINDOW_SIZE) {
				if (isReplayedPacket(seq)) {
					ret = false;
					log("testReplayWindow unexpected replayed packet");
				}
				seq++;
			}
			int size = replayWindow.size();
			if (size != SRTP_WINDOW_SIZE) {
				log("testReplayWindow after initial creation, incorrect size of vector "
						+ size);
				ret = false;
			}
			seq = 27L;
			if (!isReplayedPacket(seq)) {
				ret = false;
				log("testReplayWindow failed to spot repeated packet id " + seq);
			}
			seq = SRTP_WINDOW_SIZE + 5;
			if (isReplayedPacket(seq)) {
				log("testReplayWindow incorrectly reported repeated packet id "
						+ seq);
				ret = false;
			}
			Long l = replayWindow.getAt(0);
			long first = l.longValue();
			if (first != 5) {
				log("testReplayWindow after deleting elements, incorrect first element "
						+ first);
				ret = false;
			}
			seq = SRTP_WINDOW_SIZE + 3;
			if (isReplayedPacket(seq)) {
				log("testReplayWindow incorrectly reported repeated packet id "
						+ seq);
				ret = false;
			}
			l = replayWindow.getAt(0);
			first = l.longValue();
			if (first != 5) {
				log("testReplayWindow after adding in-window element, incorrect first element "
						+ first);
				ret = false;
			}
		}
		return ret;
	}

	private boolean transformPayload(RtpPacket rtpPacket, long roc,
			int aSeqNum, byte[] sessSaltKey, boolean isTransmitting) {
		// Returns false if error occurs
		// Uses passed parameters aROC & aSeqNum to calculate packet index
		// as, when unprotecting, its an index estimate (packets may have been
		// missed)
		// Salt Key used by initialiseIV and will differ between send & receive
		int length = rtpPacket.getPayloadLength();
		if (length == 0) {
			return false;
		}
		byte[] packet = rtpPacket.getPacket();
		if (packet == null) {
			return false;
		}
		int pos = rtpPacket.getHeaderLength();
		byte[] IV = null;
		if (isTransmitting) {
			IV = txIV;
		} else {
			IV = rxIV;
		}
		initialiseIV(IV, rtpPacket.getSscr(), aSeqNum, roc, sessSaltKey);
		if (VERBOSE) {
			log("transformPayload, after init, IV = "
					+ platform.getUtils().byteToHexString(IV));
		}

		// Calculate how many encryption iterations will be needed
		int iter = length >>> 4;

		byte[] outBuf = null; // Buffer for encrypted segment
		if (iter > 0) {
			for (int i = 0; i < iter; ++i) {
				try {
					outBuf = encryptIV(IV, isTransmitting);
				} catch (Throwable e) {
					return false;
				}
				// IV encrypted, now XOR with payload segment & append to new
				// payload
				for (int x = 0; x < 16; ++x, ++pos) {
					packet[pos] ^= outBuf[x];
				}
				// Increment IV ready for next one
				incrementIV(IV);
			}
		}
		// Now deal with the last segment if any
		int bytesLeft = length % 16;
		if (bytesLeft > 0) {
			try {
				outBuf = encryptIV(IV, isTransmitting);
			} catch (Throwable e) {
				return false;
			}
			// IV encrypted, now XOR with payload segment & append to new
			// payload
			for (int x = 0; x < bytesLeft; ++x, ++pos) {
				packet[pos] ^= outBuf[x];
			}
		}
		return true;
	}

	private boolean txSessionKeyDerivation() {
		/*
		 * Derive the session keys as described in RFC3711, section 4.3.1 -
		 * 
		 * Let "a DIV t" denote integer division of a by t, rounded down, and
		 * with the convention that "a DIV 0 = 0" for all a. We also make the
		 * convention of treating "a DIV t" as a bit string of the same length
		 * as a, and thus "a DIV t" will in general have leading zeros.
		 * 
		 * Key derivation SHALL be defined as follows in terms of <label>, an
		 * 8-bit constant (see below), master_salt and key_derivation_rate, as
		 * determined in the cryptographic context, and index, the packet index
		 * (i.e., the 48-bit ROC || SEQ for SRTP):
		 * 
		 * * Let r = index DIV key_derivation_rate (with DIV as defined above).
		 * 
		 * * Let key_id = <label> || r.
		 * 
		 * * Let x = key_id XOR master_salt, where key_id and master_salt are
		 * aligned so that their least significant bits agree (right-
		 * alignment).
		 * 
		 * Note that test data provided in rfc3711 suggests that key_id is a 7
		 * byte value whereas the above suggests a 9 byte value. i.e. for the
		 * calculation of x, key_id is right aligned with master_salt*16
		 */

		boolean res = true;
		/*
		 * Following calc not needed as for initial key derivation, index is 0
		 * long index = iROC + iFirstRtpSeq; log("txSessionKeyDerivation()");
		 * log("+++ iROC = " + iROC); log("+++ iFirstRtpSeq = " + iFirstRtpSeq);
		 * log("+++ index = " + index); long r = index >>> iKDR; log("+++ r = "
		 * + r);
		 * 
		 * Need to produce 3 keys (session encryption, session authentication
		 * and session salt) All based on same value of r, above, but with
		 * labels of 0x00, 0x01 & 0x02
		 */
		byte label = 0x00;
		if (VERBOSE) {
			platform.getLogger().log("SRTP TX session key derivation");
		}
		while (label <= 0x02) {
			if (VERBOSE) {
				logDebug("+++ label = " + label);
			}
			// Can cheat here, since only one byte of key_id affects the XOR
			byte[] x = platform.getUtils().copy(txMasterSalt);
			x[7] ^= label;
			if (VERBOSE) {
				logDebug("+++ x = " + platform.getUtils().byteToHexString(x));
			}
			if (label == 0) {
				txSessEncKey = prf_128(txMasterKey, x, txMasterKey.length);
				if (txSessEncKey == null) {
					res = false;
					break;
				}
				if (VERBOSE) {
					logDebug("+++ enc key = "
							+ platform.getUtils().byteToHexString(txSessEncKey));
				}
			} else if (label == 1) {
				txSessAuthKey = prf_128(txMasterKey, x, 20);
				if (txSessAuthKey == null) {
					res = false;
					break;
				}
				if (VERBOSE) {
					logDebug("+++ auth key = "
							+ platform.getUtils()
									.byteToHexString(txSessAuthKey));
				}
			} else {
				txSessSaltKey = prf_128(txMasterKey, x, 14);
				if (txSessSaltKey == null) {
					res = false;
					break;
				}
				if (VERBOSE) {
					logDebug("+++ salt key = "
							+ platform.getUtils()
									.byteToHexString(txSessSaltKey));
				}
			}
			label++;
		}
		if (!res) {
			// tidy up if failed
			logWarning("txSessionKeyDerivation FAILED");
			txSessEncKey = null;
			txSessAuthKey = null;
			txSessSaltKey = null;
		}
		if (VERBOSE) {
			logDebug("+++ ----------");
		}
		return res;
	}

	/**
	 * Unprotects an RTP Packet by decrypting the payload.
	 * 
	 * @param packet
	 *            RTP Packet to be unprotected
	 * @return error code, 0 = success
	 */
	public int unprotect(RtpPacket packet) {
		if (txSessAuthKey == null) {
			// Only the tx session key is set at session start, rx is done when
			// 1st packet received
			log("unprotect() called out of session");
			return UNPROTECT_SESSION_NOT_STARTED;
		}
		if (packet == null) {
			logWarning("unprotect() called with null RtpPacket");
			return UNPROTECT_NULL_PACKET;
		}
		if (previousSSRC != packet.getSscr()) {
			previousSSRC = packet.getSscr();
			// reset indexes & Seq
			rxRoc = 0;
			rxSeq = packet.getSequenceNumber();
			replayWindow.removeAllElements();
			logWarning("New SSRC detected. Resetting SRTP replay protection");
		}
		if (!receivedFirst) {
			receivedFirst = true;
			rxSeq = packet.getSequenceNumber();
			if (VERBOSE) {
				log("unprotect() iRxSeq = " + rxSeq);
			}
			if (!rxSessionKeyDerivation()) {
				logWarning("unprotect() unable to create session keys");
				return UNPROTECT_ERROR_DECRYPTING;
			}
		}
		// First need to work out the implicit srtp sequence number,
		// see rfc3711 appendix A & section 3.3.1
		// Using same naming convention as in rfc for ROC estimate (v)
		// Needs to be done before authentication as v is used as part of auth
		long v;
		int seq = packet.getSequenceNumber();
		if (rxSeq < 0x8000) {
			if ((seq - rxSeq) > 0x8000) {
				v = rxRoc - 0x10000L;
			} else {
				v = rxRoc;
			}
		} else {
			if ((rxSeq - 0x8000) > seq) {
				v = rxRoc + 0x10000L;
			} else {
				v = rxRoc;
			}
		}

		long index = v + seq;
		if (SUPER_VERBOSE) {
			log("unprotect(), seq = " + seq);
			logBuffer("unprotect(), rcvd pkt = ", packet.getPacket());
		}
		if (isReplayedPacket(index)) {
			logWarning("Replayed packet received, sequence number=#" + seq
					+ ", index=" + index);
			return UNPROTECT_REPLAYED_PACKET;
		}

		// Now need to check authentication & remove auth bytes from payload
		int originalLen = packet.getPayloadLength();
		int newLen = originalLen - HMAC_AUTH_SIZE_BYTES;

		// we'll reduce the payload length but the auth-code will still be
		// present after the payload for comparison
		int pktAuthCodePos = packet.getHeaderLength() + newLen;
		packet.setPayloadLength(newLen);
		byte[] authCode = null;
		try {
			authCode = getAuthentication(packet, v, false); // iRxSessAuthKey);
		} catch (Throwable e) {
			logError("unprotect() error getting authCode EX: " + e);
			e.printStackTrace();
			return UNPROTECT_ERROR_DECRYPTING;
		}

		if (!platform.getUtils().equals(authCode, 0, packet.getPacket(),
				pktAuthCodePos, HMAC_AUTH_SIZE_BYTES)) {
			// Auth failed
			logWarning("unprotect() Authentication failed");
			logBuffer("authCode:", authCode);
			byte[] pktAuthCode = new byte[HMAC_AUTH_SIZE_BYTES];
			System.arraycopy(packet.getPacket(), pktAuthCodePos, pktAuthCode,
					0, HMAC_AUTH_SIZE_BYTES);
			logBuffer("pktAuthCode:", pktAuthCode);
			logBuffer("iRxSessAuthKey:", rxSessAuthKey);
			log("v = " + Integer.toHexString((int) v) + " (" + v + ")");
			return UNPROTECT_INVALID_PACKET;
		}

		if (VERBOSE) {
			log("unprotect() -------- Authenticated OK --------");
		}

		// Authenticated, now unprotect the payload
		// Note the use of encryptIV() in transformPayload is correct
		// At 1st sight, might expect to use decrypt but unprotection consists
		// of XORing payload with an encrypted IV to obtain original payload
		// data

		if (!transformPayload(packet, v, seq, rxSessSaltKey, false)) {
			log("unprotect() transformPayload error, decryption failed");
			return UNPROTECT_ERROR_DECRYPTING;
		}

		// Payload now unprotected. Update the latest seq & ROC ready for next
		// packet
		if (v == rxRoc) {
			if (seq > rxSeq) {
				rxSeq = seq;
			}
		} else if (v == rxRoc + 0x10000L) {
			rxRoc += 0x10000L;
			rxSeq = seq;
		}

		if (SUPER_VERBOSE) {
			logBuffer("unprotect(), new packet - ", packet.getPacket());
		}
		return UNPROTECT_OK;
	}
}
