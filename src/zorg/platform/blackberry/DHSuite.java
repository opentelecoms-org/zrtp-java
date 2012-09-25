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

import net.rim.device.api.crypto.CryptoException;
import net.rim.device.api.crypto.CryptoTokenException;
import net.rim.device.api.crypto.CryptoUnsupportedOperationException;
import net.rim.device.api.crypto.DHCryptoSystem;
import net.rim.device.api.crypto.DHKeyAgreement;
import net.rim.device.api.crypto.DHKeyPair;
import net.rim.device.api.crypto.DHPublicKey;
import net.rim.device.api.crypto.ECCryptoSystem;
import net.rim.device.api.crypto.ECDHKeyAgreement;
import net.rim.device.api.crypto.ECKeyPair;
import net.rim.device.api.crypto.ECPublicKey;
import net.rim.device.api.crypto.InvalidCryptoSystemException;
import net.rim.device.api.crypto.UnsupportedCryptoSystemException;
import net.rim.device.api.util.Arrays;
import zorg.KeyAgreementType;
import zorg.ZrtpException;
import zorg.platform.DiffieHellmanSuite;
import zorg.platform.ZrtpLogger;

public class DHSuite implements DiffieHellmanSuite {

	private byte[] DH_PRIME = {
	        // From RFC3526, as mandated in zrtp spec, 5.1.5
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
	

	private ECCryptoSystem	ecSystem;
	private ECKeyPair	   ecKeyPair;
	private DHCryptoSystem	dhSystem;
	private DHKeyPair	   dhKeyPair;
	private KeyAgreementType dhMode;
	private ZrtpLogger logger;

	public void setLogger(ZrtpLogger logger) {
		this.logger = logger;
	}
	
	private String getDHName(KeyAgreementType mode) {
		return mode != null 
		     ? mode.toString()
		     : "<NA>";
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
		    		byte[] dhGen = new byte[384];
		    		Arrays.zero(dhGen);
		    		dhGen[383] = 0x02;
		    		dhSystem = new DHCryptoSystem(DH_PRIME, dhGen);
		    		dhKeyPair = dhSystem.createDHKeyPair();
		    		clearEcdh();
		    		break;
		        case KeyAgreementType.DH_MODE_EC25:
		        	ecSystem = new ECCryptoSystem(ECCryptoSystem.EC256R1);
		        	ecKeyPair = ecSystem.createECKeyPair();
		        	clearDh();
			        break;
		        case KeyAgreementType.DH_MODE_EC38:
		        default:
		        	ecSystem = new ECCryptoSystem(ECCryptoSystem.EC384R1);
		        	ecKeyPair = ecSystem.createECKeyPair();
		        	clearDh();
			        break;
	        }
		} catch (InvalidCryptoSystemException e) {
	        // TODO Auto-generated catch block
	        e.printStackTrace();
        } catch (UnsupportedCryptoSystemException e) {
	        // TODO Auto-generated catch block
	        e.printStackTrace();
        } catch (CryptoTokenException e) {
	        // TODO Auto-generated catch block
	        e.printStackTrace();
        } catch (CryptoUnsupportedOperationException e) {
	        // TODO Auto-generated catch block
	        e.printStackTrace();
        }
	}

	private void log(String message) {
	    if(logger == null) return;
	    logger.log(message);
    }

	public void writePublicKey(byte[] data, int offset) throws ZrtpException {
		try {
			if (useECDH()) {
				log("Writing public key for " + getDHName(dhMode));
	            ECPublicKey pub = ecKeyPair.getECPublicKey();
	            byte[] keyArray = pub.getPublicKeyData(false);
	            // This should give a key_size + 1 byte array in which 1st byte is a compression indicator
	            // Just use the rightmost key_size bytes
	            logger.log("Using EC25 key, length "+keyArray.length, keyArray);
	            logger.log("Using EC38 key, length "+keyArray.length, keyArray);
	            System.arraycopy(keyArray, 1, data, offset, keyArray.length -1);
	        } else {
	        	log("Writing public key for DH3K mode");
	        	DHPublicKey pub = dhKeyPair.getDHPublicKey();
	            byte[] keyArray = pub.getPublicKeyData();
	            System.arraycopy(keyArray, 0, data, offset, 384);
	            logger.log("Using DH3K key, length "+keyArray.length, keyArray);
	        }
		} catch (Exception e) {
			throw new ZrtpException(e);
		}
	}
	
	private boolean useECDH() {
	    return dhMode.keyType == KeyAgreementType.DH_MODE_EC25 || dhMode.keyType == KeyAgreementType.DH_MODE_EC38;
    }

	public byte[] getDhResult(byte[] aMsg, int offset, boolean isLegacyClient) throws ZrtpException  {
		try {
			log("Getting DH result for mode " + dhMode);
			if (useECDH()) {
		        int PV_LENGTH = dhMode.pvLengthInWords * 4;
		        byte[] ecpvr = new byte[PV_LENGTH + 1]; // allow one byte extra for compression indicator
		        System.arraycopy(aMsg, offset, ecpvr, 1, PV_LENGTH);
		        ecpvr[0] = (byte)0x04; // uncompressed key used
		        if(logger.isEnabled()) {
		        	logger.log("Using " + getDHName(dhMode) + " key, length "+ecpvr.length, ecpvr);
		        	logger.log("Using EC38 key, length "+ecpvr.length, ecpvr);
		        }
		        ECPublicKey ecpub;
		        ecpub = new ECPublicKey(ecSystem, ecpvr);
		        byte[] dhResult = ECDHKeyAgreement.generateSharedSecret(ecKeyPair.getECPrivateKey(), ecpub, false);
		        byte[] iDHResult = null;
		        if(!isLegacyClient) {
		        	return dhResult;
		        } else {
		        	iDHResult = new byte[PV_LENGTH];
		        	System.arraycopy(dhResult, 0, iDHResult, iDHResult.length - dhResult.length, dhResult.length);    
		        }

		        return iDHResult;
		    } else {
		        byte[] dhpvr = new byte[384];
		        System.arraycopy(aMsg, offset, dhpvr, 0, 384); 
		        DHPublicKey dhpub;
		        if(logger.isEnabled()) {
		        	logger.log("Using " + getDHName(dhMode) + " key, length "+dhpvr.length, dhpvr);
		        }
		        dhpub = new DHPublicKey(dhSystem, dhpvr);
		        byte[] iDHResult = DHKeyAgreement.generateSharedSecret(dhKeyPair.getDHPrivateKey(), dhpub, true);
		        return iDHResult;
		    }
		} catch (CryptoException e) {
			throw new ZrtpException(e);
        }
	}
	
	public void clear() {
	    clearEcdh();
	    clearDh();
    }

	private void clearDh() {
	    dhSystem  = null;
	    dhKeyPair = null;
    }

	private void clearEcdh() {
	    ecSystem  = null;
	    ecKeyPair = null;
    }

}
