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
package zorg.platform.android;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyAgreement;

import zorg.KeyAgreementType;
import zorg.ZrtpException;
import zorg.bouncycastle.asn1.ASN1InputStream;
import zorg.bouncycastle.asn1.DERBitString;
import zorg.bouncycastle.asn1.DERObject;
import zorg.bouncycastle.asn1.DERSequence;
import zorg.bouncycastle.jce.ECNamedCurveTable;
import zorg.platform.DiffieHellmanSuite;
import zorg.platform.ZrtpLogger;

public class BCDHSuite implements DiffieHellmanSuite {

    private KeyAgreementType keyType;
	private KeyPair keyPair;
	private KeyFactory keyFactory;
	private String algorithm = "ECDH";

	
	@Override
	public void clear() {
		keyPair = null;
	}

	@Override
	public byte[] getDhResult(byte[] aMsg, int offset , boolean isLegacyClient) throws ZrtpException {
		try {
			int PV_LENGTH = keyType.pvLengthInWords * 4;
			byte[] encodedKey = new byte[keyType.pvLengthInWords * 4 + 1];
			encodedKey[0] = 4;
			System.arraycopy(aMsg, offset, encodedKey, 1, encodedKey.length - 1);
			EncodedKeySpec keySpec = getSpec(encodedKey, keyPair.getPublic());
			PublicKey pub = keyFactory.generatePublic(keySpec);
			KeyAgreement agreement = KeyAgreement.getInstance(algorithm, "ZBC");
			agreement.init(keyPair.getPrivate());
			agreement.doPhase(pub, true);
			byte[] secret = agreement.generateSecret();
			byte[] iDHResult = null;
			if(!isLegacyClient) {
			    iDHResult = new byte[secret.length];
			    System.arraycopy(secret, 0, iDHResult, 0, secret.length);    
			} else {
			    iDHResult = new byte[PV_LENGTH];
	            System.arraycopy(secret, 0, iDHResult, iDHResult.length - secret.length, secret.length);    
			}
			return iDHResult;
		} catch (Exception e) {
			throw new ZrtpException(e);
		}
	}

	private byte[] getPublicKeyBytes(PublicKey publicKey) throws IOException,
			InvalidKeySpecException, NoSuchAlgorithmException {
		byte[] enc = publicKey.getEncoded();
		ASN1InputStream ap = new ASN1InputStream(enc);
		DERSequence der = (DERSequence) ap.readObject();
		DERBitString key = (DERBitString) der.getObjectAt(1);
		byte[] k = key.getBytes();
		ap.close();
		return k;
	}

	private EncodedKeySpec getSpec(byte[] encodedKey, PublicKey pub)
			throws IOException, InvalidKeySpecException,
			NoSuchAlgorithmException {
		byte[] encc = pub.getEncoded();
		ASN1InputStream ap = new ASN1InputStream(encc);
		DERSequence der = (DERSequence) ap.readObject();
		DERSequence s1 = (DERSequence) der.getObjectAt(0);

		DERBitString bit = new DERBitString(encodedKey);
		DERSequence s2 = new DERSequence(new DERObject[] { s1, bit });
		byte[] enc = s2.getEncoded();
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(enc);
		ap.close();
		return keySpec;
	}

	@Override
	public void setAlgorithm(KeyAgreementType dhMode) {
		if (keyType != null && keyType.keyType == dhMode.keyType)
			return;
		keyType = dhMode;
		KeyPairGenerator kpg = null;
		try {
			switch (keyType.keyType) {
			case KeyAgreementType.DH_MODE_DH3K:
				algorithm = "DH";
				kpg = KeyPairGenerator.getInstance(algorithm, "ZBC");
				kpg.initialize(576);
				keyPair = kpg.genKeyPair();
				break;
			case KeyAgreementType.DH_MODE_EC25:
				algorithm = "ECDH";
				kpg = KeyPairGenerator.getInstance(algorithm, "ZBC");
				// kpg.initialize(256);
				kpg.initialize(ECNamedCurveTable.getParameterSpec("P-256"));
				keyPair = kpg.genKeyPair();
				break;
			case KeyAgreementType.DH_MODE_EC38:
				algorithm = "ECDH";
				kpg = KeyPairGenerator.getInstance(algorithm, "ZBC");
				// kpg.initialize(384);
				kpg.initialize(ECNamedCurveTable.getParameterSpec("P-384"));
				keyPair = kpg.genKeyPair();
				break;
			default:
				break;
			}
			keyFactory = KeyFactory.getInstance(algorithm, "ZBC");
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	@Override
	public void setLogger(ZrtpLogger logger) {
	}

	@Override
	public void writePublicKey(byte[] data, int offset) throws ZrtpException {
		try {
			byte[] k = getPublicKeyBytes(keyPair.getPublic());
			System.arraycopy(k, 1, data, offset, k.length - 1);
		} catch (Exception e) {
			throw new ZrtpException(e);
		}
	}

}
