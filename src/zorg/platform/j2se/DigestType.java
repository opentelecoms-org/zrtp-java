package zorg.platform.j2se;

public enum DigestType {

	SHA1 ("SHA-1", "HmacSHA1"),
	SHA256 ("SHA-256", "HmacSHA256"),
	SHA384 ("SHA-384", "HmacSHA384");
	
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
	
}
