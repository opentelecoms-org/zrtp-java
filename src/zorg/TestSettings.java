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


public class TestSettings {
	
	public static final boolean TEST = true;
	public static boolean TEST_ZRTP_CACHE_MISMATCH;
	public static boolean TEST_ZRTP_WRONG_ZRTP_HASH;
	public static boolean TEST_ZRTP_WRONG_HMAC_HELLO;
	public static boolean TEST_ZRTP_WRONG_HMAC_COMMIT;
	public static boolean TEST_ZRTP_WRONG_HMAC_DHPART1;
	public static boolean TEST_ZRTP_WRONG_HMAC_DHPART2;
	public static boolean TEST_ZRTP_WRONG_HMAC_CONFIRM;
	public static boolean TEST_ZRTP_WRONG_HVI;
	public static boolean TEST_ZRTP_ZID_COLLISION;
	
	public static boolean KEY_TYPE_DH3K;
	public static boolean KEY_TYPE_EC25;
	public static boolean KEY_TYPE_EC38;

	// TODO test case not implemented yet: how to do it?
	public static boolean TEST_ZRTP_BAD_PUBLIC_KEY;

	static {
		initDefaults();
	}
	
	public static void initDefaults() {
		TEST_ZRTP_WRONG_HMAC_HELLO   = false;
		TEST_ZRTP_WRONG_HMAC_COMMIT  = false;
		TEST_ZRTP_WRONG_HMAC_DHPART1 = false;
		TEST_ZRTP_WRONG_HMAC_DHPART2 = false;
		TEST_ZRTP_WRONG_HMAC_CONFIRM = false;
		TEST_ZRTP_WRONG_ZRTP_HASH    = false;
		TEST_ZRTP_CACHE_MISMATCH     = false;
		TEST_ZRTP_ZID_COLLISION      = false;
		TEST_ZRTP_BAD_PUBLIC_KEY     = false;
		TEST_ZRTP_WRONG_HVI          = false;	
		
		KEY_TYPE_DH3K                = false;
		KEY_TYPE_EC25                = false;
		KEY_TYPE_EC38                = true;

	}	
}
