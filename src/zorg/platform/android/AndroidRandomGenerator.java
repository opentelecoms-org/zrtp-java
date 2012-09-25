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

import java.security.SecureRandom;

public class AndroidRandomGenerator implements zorg.platform.RandomGenerator {

    private static AndroidRandomGenerator instance;
    private static SecureRandom randomGenerator = null;
	private boolean initialized = false;

    private AndroidRandomGenerator() {
        instance = this;
        randomGenerator = new SecureRandom();
        seed();
    }

    public static AndroidRandomGenerator getInstance() {
        if (instance == null) {
            new AndroidRandomGenerator();
        }
        return instance;
    }
    
    @Override
    public boolean isInitialized() {
    	return initialized;
    }


    /**
     * Seed the RandomGenerator from a java.security.SecureRandom source
     */
    private void seed() {
    	byte [] initArray = new byte[64];
    	randomGenerator.nextBytes(initArray);
        seed(initArray);
    }

    @Override
    public void seedUsingPcmAudio(byte[] data) {
        byte[] key = new byte[64];
        for (int i = 0; i < key.length; i++) {
            int x = 0;
            //Pick 4 random bytes from the PCM audio data, from each of the bytes 
            //take the two least significant bits and concatenate them to form
            //the i-th byte in the seed key
            for (int j = 0; j < 4; j++) {
                x = (x << 2) | (3 & data[randomGenerator.nextInt(data.length)]);
            }
            key[i] = (byte) x;
        }
        seed(key);
        initialized = true;
    }

    /**
     * Seed the random generator with a standard 20 to 64 byte byte array.
     *
     * @param key The seed key to use. Note that seed.length must be between 20
     * and 64 bytes.
     */
    private void seed(byte[] key) {
    	randomGenerator.setSeed(key);
    }

    @Override
    public int getInt() {
        byte[] rand = new byte[4];
        randomGenerator.nextBytes(rand);
        int result = rand[0];
        for (int i = 1; i < 4; i++) {
            result = (result << 8) | rand[i];
        }
        return result;
    }

    @Override
    public void getBytes(byte[] buffer) {
       	randomGenerator.nextBytes(buffer);
    }

    @Override
    public byte[] getBytes(int length) {
    	byte[] randomBytes = new byte[length];
    	randomGenerator.nextBytes(randomBytes);
    	return randomBytes;
    }

    @Override
    public void getBytes(byte[] buffer, int offset, int length) {
    	byte [] random = new byte[length];
    	randomGenerator.nextBytes(random);
		System.arraycopy(random, 0, buffer, offset, length);
    }

    @Override
	public byte getByte() {
	    return getBytes(1)[0];
    }
}
