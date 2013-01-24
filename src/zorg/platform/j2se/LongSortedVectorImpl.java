package zorg.platform.j2se;

import java.util.Vector;

import zorg.platform.LongSortedVector;


public class LongSortedVectorImpl implements LongSortedVector {
	
	Vector<Long> vector = new Vector<Long>();
	
	public LongSortedVectorImpl() {
		
	}

	@Override
	public void removeAllElements() {
		vector.removeAllElements();
	}

	@Override
	public int size() {
		return vector.size();
	}

	@Override
	public int find(Long element) {
		return vector.indexOf(element);
	}

	@Override
	public void addElement(Long element) {
		for(int i = 0; i < vector.size(); i++) {
			if(vector.get(i).compareTo(element) >= 0) {
				vector.insertElementAt(element, i);
				return;
			}
		}
		vector.add(element);
	}

	@Override
	public Long getAt(int index) {
		return vector.get(index);
	}

	@Override
	public void removeElementAt(int index) {
		vector.remove(index);
	}

}
