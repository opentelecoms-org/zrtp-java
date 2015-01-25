package zorg.platform.j2se;

import java.util.Vector;

import zorg.platform.LongSortedVector;


public class LongSortedVectorImpl implements LongSortedVector {
	
	Vector vector = new Vector();
	
	public LongSortedVectorImpl() {
		
	}

	public void removeAllElements() {
		vector.removeAllElements();
	}

	public int size() {
		return vector.size();
	}

	public int find(Long element) {
		return vector.indexOf(element);
	}

	public void addElement(Long element) {
		for(int i = 0; i < vector.size(); i++) {
			Long l = (Long)vector.get(i);
			if(l.compareTo(element) >= 0) {
				vector.insertElementAt(element, i);
				return;
			}
		}
		vector.add(element);
	}

	public Long getAt(int index) {
		return (Long)vector.get(index);
	}

	public void removeElementAt(int index) {
		vector.remove(index);
	}

}
