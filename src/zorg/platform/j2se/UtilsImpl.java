package zorg.platform.j2se;

import zorg.platform.LongSortedVector;

public class UtilsImpl implements zorg.platform.Utils {
	
	public UtilsImpl() {
		
	}

	@Override
	public boolean equals(byte[] array1, int offset1, byte[] array2,
			int offset2, int length) {
		// FIXME - performance
		for(int i = 0; i < length; i++) {
			if(array1[offset1 + i] != array2[offset2 + i])
				return false;
		}
		return true;
	}
	
	final static String hexChars = "0123456789abcdef";

	@Override
	public String byteToHexString(byte[] buffer, int offset, int length) {
		if(buffer == null)
			return "<null buffer>";
		// FIXME - performance
		StringBuilder sb = new StringBuilder();
		for(int i = 0; i < length; i++) {
			byte b = buffer[offset + i];
			sb.append(hexChars.charAt((b & 0xf0) >> 4));
			sb.append(hexChars.charAt(b&0xf));
		}
		return sb.toString();
	}

	@Override
	public String byteToHexString(byte[] buffer) {
		// FIXME - performance
		if(buffer == null)
			return "<null buffer>";
		return byteToHexString(buffer, 0, buffer.length);
	}

	@Override
	public int getInt(byte[] data, int begin, int end) {
		// TODO Auto-generated method stub
		throw new RuntimeException("not implemented");
	}

	@Override
	public void zero(byte[] data) {
		// FIXME - performance
		for(int i = 0; i < data.length; i++)
			data[i] = 0;
	}

	@Override
	public byte[] copy(byte[] data) {
		// FIXME - performance
		byte[] _data = new byte[data.length];
		for(int i = 0; i < data.length; i++)
			_data[i] = data[i];
		return _data;
	}

	@Override
	public LongSortedVector createSortedVector() {
		return new LongSortedVectorImpl();
	}

}
