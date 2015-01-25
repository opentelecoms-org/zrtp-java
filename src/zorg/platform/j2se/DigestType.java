package zorg.platform.j2se;

public class DigestType {

	public final static DigestType SHA1 = new DigestType("SHA-1", "HmacSHA1");
	public final static DigestType SHA256 = new DigestType("SHA-256", "HmacSHA256");
	public final static DigestType SHA384 = new DigestType("SHA-384", "HmacSHA384");
	
	String jceName;
	String jceHmacName;
	
	DigestType(String jceName, String jceHmacName) {
		this.jceName = jceName;
		this.jceHmacName = jceHmacName;
	}
	
	public String getJCEName() {
		return jceName;
	}
	
	public String getJCEHmacName() {
		return jceHmacName;
	}
	
	public String name() {
		return new String(getJCEName());
	}

	public String toString() {
		return name();
	}
}
