package zorg;

public class AuthenticationMode {
	
	public final static AuthenticationMode UNDEFINED = new AuthenticationMode(null, 0 );
	public final static AuthenticationMode HS80 = new AuthenticationMode(new byte[] { 'H', 'S', '8', '0' }, 80 );
	public final static AuthenticationMode HS32 = new AuthenticationMode(new byte[] { 'H', 'S', '3', '2' }, 32 );
	
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
	
	public String name() {
		return new String(getSymbol());
	}
	
	public String toString() {
		return name();
	}

}
