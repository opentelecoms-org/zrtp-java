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
package zorg.platform.blackberry;

import zorg.ZrtpCacheEntry;
import net.rim.device.api.util.Persistable;

public class BBZrtpCacheEntry implements Persistable,ZrtpCacheEntry {

	byte[] mData;
	String mNumber;
	
	public BBZrtpCacheEntry() {
    }
    
    public BBZrtpCacheEntry(byte[] aData, String aNumber) {
        mData = aData;
        mNumber = aNumber;
    }
    
    public void setData(byte[] data) {
    	mData = data;
    }
    
    public void setNumber(String number) {
    	 mNumber = number;
    }
    
    public byte[] getData() {
        return mData;
    }
    
    public String getNumber() {
        return mNumber;
    }
}
