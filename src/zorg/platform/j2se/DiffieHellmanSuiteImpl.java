package zorg.platform.j2se;

import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;

import zorg.KeyAgreementType;
import zorg.ZrtpException;
import zorg.platform.DiffieHellmanSuite;
import zorg.platform.ZrtpLogger;


public class DiffieHellmanSuiteImpl implements DiffieHellmanSuite {
	
	private static final String ALGORITHM_DH = "DH";
	private static final String ALGORITHM_ECDH = "ECDH";
	private static final int DH_EXP_LENGTH = 256;   // = twice the AES key length = 2 * 128 bits
	
	// Copied directly from RFC 3526, 2012-02-13
	public String DH_PRIME_S = 
      		"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
      		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
      		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
      		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
      		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
      		"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
      		"83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
      		"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
      		"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
      		"DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
      		"15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64" +
      		"ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" +
      		"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B" +
      		"F12FFA06D98A0864D87602733EC86A64521F2B18177B200C" +
      		"BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31" +
      		"43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";


	
	private byte[] DH_PRIME = {
	        // From RFC3526, as mandated in zrtp spec, 5.1.5
			(byte) 0x00, // as BigInteger interprets this as two's complement, we need
			             // to insert leading 0
	        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
	        (byte) 0xFF, (byte) 0xFF, (byte) 0xC9, (byte) 0x0F, (byte) 0xDA, (byte) 0xA2,
	        (byte) 0x21, (byte) 0x68, (byte) 0xC2, (byte) 0x34, (byte) 0xC4, (byte) 0xC6,
	        (byte) 0x62, (byte) 0x8B, (byte) 0x80, (byte) 0xDC, (byte) 0x1C, (byte) 0xD1,
	        (byte) 0x29, (byte) 0x02, (byte) 0x4E, (byte) 0x08, (byte) 0x8A, (byte) 0x67,
	        (byte) 0xCC, (byte) 0x74, (byte) 0x02, (byte) 0x0B, (byte) 0xBE, (byte) 0xA6,
	        (byte) 0x3B, (byte) 0x13, (byte) 0x9B, (byte) 0x22, (byte) 0x51, (byte) 0x4A,
	        (byte) 0x08, (byte) 0x79, (byte) 0x8E, (byte) 0x34, (byte) 0x04, (byte) 0xDD,
	        (byte) 0xEF, (byte) 0x95, (byte) 0x19, (byte) 0xB3, (byte) 0xCD, (byte) 0x3A,
	        (byte) 0x43, (byte) 0x1B, (byte) 0x30, (byte) 0x2B, (byte) 0x0A, (byte) 0x6D,
	        (byte) 0xF2, (byte) 0x5F, (byte) 0x14, (byte) 0x37, (byte) 0x4F, (byte) 0xE1,
	        (byte) 0x35, (byte) 0x6D, (byte) 0x6D, (byte) 0x51, (byte) 0xC2, (byte) 0x45,
	        (byte) 0xE4, (byte) 0x85, (byte) 0xB5, (byte) 0x76, (byte) 0x62, (byte) 0x5E,
	        (byte) 0x7E, (byte) 0xC6, (byte) 0xF4, (byte) 0x4C, (byte) 0x42, (byte) 0xE9,
	        (byte) 0xA6, (byte) 0x37, (byte) 0xED, (byte) 0x6B, (byte) 0x0B, (byte) 0xFF,
	        (byte) 0x5C, (byte) 0xB6, (byte) 0xF4, (byte) 0x06, (byte) 0xB7, (byte) 0xED,
	        (byte) 0xEE, (byte) 0x38, (byte) 0x6B, (byte) 0xFB, (byte) 0x5A, (byte) 0x89,
	        (byte) 0x9F, (byte) 0xA5, (byte) 0xAE, (byte) 0x9F, (byte) 0x24, (byte) 0x11,
	        (byte) 0x7C, (byte) 0x4B, (byte) 0x1F, (byte) 0xE6, (byte) 0x49, (byte) 0x28,
	        (byte) 0x66, (byte) 0x51, (byte) 0xEC, (byte) 0xE4, (byte) 0x5B, (byte) 0x3D,
	        (byte) 0xC2, (byte) 0x00, (byte) 0x7C, (byte) 0xB8, (byte) 0xA1, (byte) 0x63,
	        (byte) 0xBF, (byte) 0x05, (byte) 0x98, (byte) 0xDA, (byte) 0x48, (byte) 0x36,
	        (byte) 0x1C, (byte) 0x55, (byte) 0xD3, (byte) 0x9A, (byte) 0x69, (byte) 0x16,
	        (byte) 0x3F, (byte) 0xA8, (byte) 0xFD, (byte) 0x24, (byte) 0xCF, (byte) 0x5F,
	        (byte) 0x83, (byte) 0x65, (byte) 0x5D, (byte) 0x23, (byte) 0xDC, (byte) 0xA3,
	        (byte) 0xAD, (byte) 0x96, (byte) 0x1C, (byte) 0x62, (byte) 0xF3, (byte) 0x56,
	        (byte) 0x20, (byte) 0x85, (byte) 0x52, (byte) 0xBB, (byte) 0x9E, (byte) 0xD5,
	        (byte) 0x29, (byte) 0x07, (byte) 0x70, (byte) 0x96, (byte) 0x96, (byte) 0x6D,
	        (byte) 0x67, (byte) 0x0C, (byte) 0x35, (byte) 0x4E, (byte) 0x4A, (byte) 0xBC,
	        (byte) 0x98, (byte) 0x04, (byte) 0xF1, (byte) 0x74, (byte) 0x6C, (byte) 0x08,
	        (byte) 0xCA, (byte) 0x18, (byte) 0x21, (byte) 0x7C, (byte) 0x32, (byte) 0x90,
	        (byte) 0x5E, (byte) 0x46, (byte) 0x2E, (byte) 0x36, (byte) 0xCE, (byte) 0x3B,
	        (byte) 0xE3, (byte) 0x9E, (byte) 0x77, (byte) 0x2C, (byte) 0x18, (byte) 0x0E,
	        (byte) 0x86, (byte) 0x03, (byte) 0x9B, (byte) 0x27, (byte) 0x83, (byte) 0xA2,
	        (byte) 0xEC, (byte) 0x07, (byte) 0xA2, (byte) 0x8F, (byte) 0xB5, (byte) 0xC5,
	        (byte) 0x5D, (byte) 0xF0, (byte) 0x6F, (byte) 0x4C, (byte) 0x52, (byte) 0xC9,
	        (byte) 0xDE, (byte) 0x2B, (byte) 0xCB, (byte) 0xF6, (byte) 0x95, (byte) 0x58,
	        (byte) 0x17, (byte) 0x18, (byte) 0x39, (byte) 0x95, (byte) 0x49, (byte) 0x7C,
	        (byte) 0xEA, (byte) 0x95, (byte) 0x6A, (byte) 0xE5, (byte) 0x15, (byte) 0xD2,
	        (byte) 0x26, (byte) 0x18, (byte) 0x98, (byte) 0xFA, (byte) 0x05, (byte) 0x10,
	        (byte) 0x15, (byte) 0x72, (byte) 0x8E, (byte) 0x5A, (byte) 0x8A, (byte) 0xAA,
	        (byte) 0xC4, (byte) 0x2D, (byte) 0xAD, (byte) 0x33, (byte) 0x17, (byte) 0x0D,
	        (byte) 0x04, (byte) 0x50, (byte) 0x7A, (byte) 0x33, (byte) 0xA8, (byte) 0x55,
	        (byte) 0x21, (byte) 0xAB, (byte) 0xDF, (byte) 0x1C, (byte) 0xBA, (byte) 0x64,
	        (byte) 0xEC, (byte) 0xFB, (byte) 0x85, (byte) 0x04, (byte) 0x58, (byte) 0xDB,
	        (byte) 0xEF, (byte) 0x0A, (byte) 0x8A, (byte) 0xEA, (byte) 0x71, (byte) 0x57,
	        (byte) 0x5D, (byte) 0x06, (byte) 0x0C, (byte) 0x7D, (byte) 0xB3, (byte) 0x97,
	        (byte) 0x0F, (byte) 0x85, (byte) 0xA6, (byte) 0xE1, (byte) 0xE4, (byte) 0xC7,
	        (byte) 0xAB, (byte) 0xF5, (byte) 0xAE, (byte) 0x8C, (byte) 0xDB, (byte) 0x09,
	        (byte) 0x33, (byte) 0xD7, (byte) 0x1E, (byte) 0x8C, (byte) 0x94, (byte) 0xE0,
	        (byte) 0x4A, (byte) 0x25, (byte) 0x61, (byte) 0x9D, (byte) 0xCE, (byte) 0xE3,
	        (byte) 0xD2, (byte) 0x26, (byte) 0x1A, (byte) 0xD2, (byte) 0xEE, (byte) 0x6B,
	        (byte) 0xF1, (byte) 0x2F, (byte) 0xFA, (byte) 0x06, (byte) 0xD9, (byte) 0x8A,
	        (byte) 0x08, (byte) 0x64, (byte) 0xD8, (byte) 0x76, (byte) 0x02, (byte) 0x73,
	        (byte) 0x3E, (byte) 0xC8, (byte) 0x6A, (byte) 0x64, (byte) 0x52, (byte) 0x1F,
	        (byte) 0x2B, (byte) 0x18, (byte) 0x17, (byte) 0x7B, (byte) 0x20, (byte) 0x0C,
	        (byte) 0xBB, (byte) 0xE1, (byte) 0x17, (byte) 0x57, (byte) 0x7A, (byte) 0x61,
	        (byte) 0x5D, (byte) 0x6C, (byte) 0x77, (byte) 0x09, (byte) 0x88, (byte) 0xC0,
	        (byte) 0xBA, (byte) 0xD9, (byte) 0x46, (byte) 0xE2, (byte) 0x08, (byte) 0xE2,
	        (byte) 0x4F, (byte) 0xA0, (byte) 0x74, (byte) 0xE5, (byte) 0xAB, (byte) 0x31,
	        (byte) 0x43, (byte) 0xDB, (byte) 0x5B, (byte) 0xFC, (byte) 0xE0, (byte) 0xFD,
	        (byte) 0x10, (byte) 0x8E, (byte) 0x4B, (byte) 0x82, (byte) 0xD1, (byte) 0x20,
	        (byte) 0xA9, (byte) 0x3A, (byte) 0xD2, (byte) 0xCA, (byte) 0xFF, (byte) 0xFF,
	        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF };
	
	KeyPairGenerator ecKeyGen;
	KeyPair ecKeyPair;
	
	KeyPairGenerator dhKeyGen;
	KeyPair dhKeyPair;
	
	private KeyAgreementType dhMode;
	private ZrtpLogger logger;
	
	SecureRandom sr;
	
	BigInteger dhP;
	BigInteger dhG;
	
	public DiffieHellmanSuiteImpl() {
		try {
			sr = SecureRandom.getInstance(CryptoUtilsImpl.DEFAULT_RANDOM_ALGORITHM);
			byte[] dhGen = new byte[384];
    		new UtilsImpl().zero(dhGen);
    		dhGen[383] = 0x02;
    		//dhP = new BigInteger(DH_PRIME);
    		dhP = new BigInteger(DH_PRIME_S, 16);
    		dhG = new BigInteger(dhGen);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			throw new RuntimeException("Failed init Diffie-Hellman: " + e.getClass().getName() + ": " + e.getMessage());
		}
	}

	public void setLogger(ZrtpLogger logger) {
		this.logger = logger;
	}
	
	private String getDHName(KeyAgreementType mode) {
		return mode != null 
		     ? mode.toString()
		     : "<NA>";
	}
	
	private void setupEC(int bits) throws NoSuchAlgorithmException {
		ecKeyGen = KeyPairGenerator.getInstance(ALGORITHM_ECDH);
		ecKeyGen.initialize(bits);
		ecKeyPair = ecKeyGen.generateKeyPair();
		clearDh();
	}
	
	/**
	 * DH3K RIM implementation is currently buggy and DOES NOT WORK!!!
	 */
	public void setAlgorithm(KeyAgreementType dh) 
	{
		log("DH algorithm set: " + getDHName(dhMode) + " -> " + getDHName(dh));
		try {
			if(dhMode != null && dh.keyType == dhMode.keyType) return;
			dhMode = dh;
			switch (dhMode.keyType) {
		        case KeyAgreementType.DH_MODE_DH3K:
		    		DHParameterSpec paramSpec = new DHParameterSpec(dhP, dhG, DH_EXP_LENGTH);
		    		dhKeyGen = KeyPairGenerator.getInstance(ALGORITHM_DH);
		    		dhKeyGen.initialize(paramSpec, sr);
		    		dhKeyPair = dhKeyGen.generateKeyPair();
		    		clearEcdh();
		    		break;
		        case KeyAgreementType.DH_MODE_EC25:
		        	setupEC(256);
			        break;
		        case KeyAgreementType.DH_MODE_EC38:
		        default:
		        	setupEC(384);
			        break;
	        }
		} catch (Exception e) {
	        // TODO Auto-generated catch block
	        e.printStackTrace();
	        throw new RuntimeException("Failed init Diffie-Hellman: " + e.getClass().getName() + ": " + e.getMessage() + ", bitlength p = " + dhP.bitCount());
        }
	}

	private void log(String message) {
	    if(logger == null)
	    	return;
	    logger.log(message);
    }
	
	private void log(String message, byte[] b) {
	    if(logger == null)
	    	return;
	    logger.log(message, b);
    }

	public void writePublicKey(byte[] data, int offset) throws ZrtpException {
		try {
			if (useECDH()) {
				// RFC 6189 s4.4.1.1:
				// http://tools.ietf.org/html/rfc6189#section-4.4.1.1
				// For Elliptic Curve DH, pvi is calculated and formatted according to
				// the ECDH specification in Section 5.1.5, which refers in detail to
				// certain sections of NIST SP 800-56A [NIST-SP800-56A].
				//  From s5.1.5:
				// Both the X and Y coordinates of the point on the curve
				// are sent, in the first and second half of the ECDH public value,
				// respectively.  The ECDH result returns only the X coordinate, as
				// specified in SP 800-56A.  Useful strategies for implementing ECC may
				// be found in [RFC6090].
				//  For EC25, we expect 64 bytes
				//  For EC38, we expect 96 bytes
				// *** FIXME *** RFC doesn't specify endianness for ECDH
				//   we are sending big endian, as per normal DH3K, it will work with
				//   other implementations using the same code
				log("Writing public key for " + getDHName(dhMode));
	            ECPublicKey pub = (ECPublicKey)ecKeyPair.getPublic();
	            ECPoint w = pub.getW();
	            BigInteger x = w.getAffineX();
	            BigInteger y = w.getAffineY();
	            int expected = dhMode.pvLengthInWords * 4 / 2;
	            writeToBuf(data, offset, expected, x);
	            int _offset = offset + expected;
	            writeToBuf(data, _offset, expected, y);
	        } else {
		    	// Get the DH Public key and write it out in the wire format for the DHPart1 or DHPart2 packet
		    	// From the ZRTP spec:
		    	//  1 word = 4 octets = 4 bytes = 32 bits
		    	//  For DH3K algorithm, pvr size = 96 words = 384 bytes = 3072 bits
		    	//    - same as the size of the prime
		    	//    - big endian (most significant byte first)
		    	//    - leading zeros intact
		    	//    - refer to RFC 3526 s4
	        	DHPublicKey pub = (DHPublicKey)dhKeyPair.getPublic();
	        	BigInteger y = pub.getY();
	        	log("Writing public key for DH3K mode: " + y);
	        	writeToBuf(data, offset, dhMode.pvLengthInWords * 4, y);
	            //log("Using DH3K key, length "+(keyArray.length + _offset), keyArray);
	        }
		} catch (Exception e) {
			throw new ZrtpException(e);
		}
	}
	
	protected void writeToBuf(byte[] data, int offset, int expected, BigInteger v) {
		if(v.signum() == -1) // the padding algorithm below won't work for a negative sign bit
    		throw new RuntimeException("Can't handle a negative BigInteger in public key");
        byte[] _r = v.toByteArray();
        log("Writing key bytes: " + v.toString(16));
        // Check if the high order byte is 0 (because the high order bit of the next byte might be 1)
        int permittedLength = expected;
        if(_r.length > 0 && _r[0] == 0)
        	permittedLength++;
        if(_r.length > permittedLength)
        	throw new RuntimeException("Can't handle a BigInteger bigger than expected bit length for DH public key: " + _r.length + " > " + expected);
        int _offset = expected - _r.length; // for 0 padding
        if(_offset < 0)
        	_offset = 0;
        for(int i = 0; i < _offset; i++)
        	data[offset + i] = 0;  // put leading zeros
        if(permittedLength == expected)
        	System.arraycopy(_r, 0, data, offset + _offset, _r.length);
        else
        	System.arraycopy(_r, 1, data, offset + _offset, _r.length - 1);
	}
	
	protected BigInteger readFromBuf(byte[] data, int offset, int expected) {
		// BigInteger constructor expects two's-complement, so we must insert
		// a leading 0 to guarantee that it will be treated as a positive number
		byte[] _buf = new byte[expected + 1];
		_buf[0] = 0;
		for(int i = 0; i < expected; i++)
			_buf[i + 1] = data[offset + i];
		log("Reading key bytes: ", _buf);
		return new BigInteger(_buf);
	}
	
	private boolean useECDH() {
	    return dhMode.keyType == KeyAgreementType.DH_MODE_EC25 || dhMode.keyType == KeyAgreementType.DH_MODE_EC38;
    }

	public byte[] getDhResult(byte[] aMsg, int offset, boolean isLegacyClient) throws ZrtpException  {
		try {
			log("Getting DH result for mode " + dhMode);
			if (useECDH()) {
				
				int expected = dhMode.pvLengthInWords * 4 / 2;
				BigInteger x = readFromBuf(aMsg, offset, expected);
				BigInteger y = readFromBuf(aMsg, offset+expected, expected);
				ECPoint w = new ECPoint(x, y);
				KeyFactory keyFac = KeyFactory.getInstance(ALGORITHM_ECDH);
				ECPublicKeySpec ecPKSpec = new ECPublicKeySpec(w, null);
				KeyAgreement agree = KeyAgreement.getInstance(ALGORITHM_ECDH);
		    	agree.init(dhKeyPair.getPrivate());
		    	agree.doPhase(keyFac.generatePublic(ecPKSpec), true);
		        //as stated in Section 4.4.1.4 in ECDH P-256 mode is in fact 32 bytes
		        //as stated in Section 4.4.1.4 in ECDH P-384 mode is in fact 48 bytes
		    	byte[] iDHResult = agree.generateSecret();
		        return iDHResult;
		    } else {
		    	
		    	int expected = dhMode.pvLengthInWords * 4;
		    	BigInteger y = readFromBuf(aMsg, offset, expected);
		    	log("Read public key for DH3K mode: " + y);
		    	KeyFactory keyFac = KeyFactory.getInstance(ALGORITHM_DH);
		    	DHPublicKeySpec dhPKSpec = new DHPublicKeySpec(y, dhP, dhG);
		    	KeyAgreement agree = KeyAgreement.getInstance(ALGORITHM_DH);
		    	agree.init(dhKeyPair.getPrivate());
		    	agree.doPhase(keyFac.generatePublic(dhPKSpec), true);
		    	byte[] iDHResult = agree.generateSecret();
		    	log("DH shared secret: ", iDHResult);
		        return iDHResult;
		    }
		} catch (Exception e) {
			throw new ZrtpException(e);
        }
	}
	
	public void clear() {
	    clearEcdh();
	    clearDh();
    }

	private void clearDh() {
	    dhKeyGen  = null;
	    dhKeyPair = null;
    }

	private void clearEcdh() {
	    ecKeyGen  = null;
	    ecKeyPair = null;
    }

}
