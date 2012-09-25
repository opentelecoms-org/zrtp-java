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

import java.util.ArrayList;
import java.util.Collections;

import zorg.platform.LongSortedVector;

public class SortedVector implements LongSortedVector {

	private ArrayList<Long> inner = new ArrayList<Long>();

	@Override
	public void addElement(Long element) {
		inner.add(element);
		sort();
	}

	@Override
	public int find(Long element) {
		return inner.indexOf(element);
	}

	@Override
	public Long getAt(int index) {
		return inner.get(index);
	}

	@Override
	public void removeAllElements() {
		inner.clear();
	}

	@Override
	public void removeElementAt(int index) {
		inner.remove(index);
	}

	@Override
	public int size() {
		return inner.size();
	}

	private void sort() {
		Collections.sort(inner);
	}
}
