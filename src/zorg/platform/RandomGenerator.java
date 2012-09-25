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
package zorg.platform;

/**
 * Random generator produces randomness in different types and quantity
 */
public interface RandomGenerator {

	/** get a random byte */
	byte getByte();

    /**
     * Generates random bytes filling the given buffer entirely
     * 
     * @param buffer The byte array to fill with random bytes
     */
	void getBytes(byte[] data);

    /**
     * Inserts random bytes into the given buffer starting at the specified 
     * array index offset
     * 
     * @param buffer The buffer to store the random bytes
     * @param offset The start, or initial position, of the data within the buffer
     * @param length The number of random bytes to store

     */
	void getBytes(byte[] data, int offset, int length);

    /**
     * Generate a specified length of random bytes, returning them as a byte
     * array of the specified size
     *
     * @param length The number of random bytes to generate
     * @return A byte array containing the random bytes
     */
	byte[] getBytes(int length);

    /**
     * Returns a random integer
     *
     * @return A random value of type int
     */
	int getInt();

    /**
     * Seed the random generator with 2 least significant bits of randomly picked
     * bytes within the provided PCM audio data
     *
     * @param data PCM audio data
     */
	void seedUsingPcmAudio(byte[] mEntropyBytes);

	/** returns true if the RandomGenerator is inizialized */
	boolean isInitialized();

}
