package zorg;

public enum AuthenticationMode {
	

	UNDEFINED ( null, 0 ),
	HS80 ( new byte[] { 'H', 'S', '8', '0' }, 80 ),
	HS32 ( new byte[] { 'H', 'S', '3', '2' }, 32 );
	
    private byte[] symbol;
	private int tagBits;

	AuthenticationMode(byte[] symbol, int tagBits) {
	    this.symbol = symbol;
	    this.tagBits = tagBits;
	}
	
	public byte[] getSymbol() {
		return symbol;
	}

	public int getTagBits() {
		return tagBits;
	}

	public int getTagBytes() {
		return getTagBits() / 8;
	}

}
