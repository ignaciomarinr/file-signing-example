import java.io.Serializable;

public class SecureFile implements Serializable {
	private static final long serialVersionUID = -3829420415767283822L;
	
	public byte[] encFile;
	public byte[] encSessionKey;
	public byte[] sign;
}