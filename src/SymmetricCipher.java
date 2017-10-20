public class SymmetricCipher {
	byte[] byteKey;
	SymmetricEncryption s;
	SymmetricEncryption d;

	// Initialization Vector (fixed)
	byte[] iv = new byte[] { (byte) 49, (byte) 50, (byte) 51, (byte) 52, (byte) 53, (byte) 54, (byte) 55, (byte) 56,
			(byte) 57, (byte) 48, (byte) 49, (byte) 50, (byte) 51, (byte) 52, (byte) 53, (byte) 54 };

	/*************************************************************************************/
	/* Constructor method */
	/*************************************************************************************/
	public SymmetricCipher() { }

	/*************************************************************************************/
	/* Method to encrypt using AES/CBC/PKCS5 */
	/*************************************************************************************/
	public byte[] encryptCBC(byte[] input, byte[] byteKey) throws Exception {
		byte[] ciphertext = null;

		// Generate the plaintext with padding
		input = addPkcs5Padding(input);

		// Generate the ciphertext
		ciphertext = new byte[input.length];
		s = new SymmetricEncryption(byteKey);
		byte[] prev = iv;

		for (int i = 0; i < input.length; i += 16) {
			byte[] inputChunk = new byte[16];
			System.arraycopy(input, i, inputChunk, 0, 16);

			byte[] cipheredChunk = s.encryptBlock(xor(inputChunk, prev));

			System.arraycopy(cipheredChunk, 0, ciphertext, i, 16);

			prev = cipheredChunk;
		}

		return ciphertext;
	}

	/*************************************************************************************/
	/* Method to decrypt using AES/CBC/PKCS5 */
	/*************************************************************************************/
	public byte[] decryptCBC(byte[] input, byte[] byteKey) throws Exception {
		byte[] finalplaintext = null;

		// Generate the plaintext
		finalplaintext = new byte[input.length];
		d = new SymmetricEncryption(byteKey);
		byte[] prev = iv;

		for (int i = 0; i < input.length; i += 16) {
			byte[] inputChunk = new byte[16];
			System.arraycopy(input, i, inputChunk, 0, 16);

			byte[] plaintextChunk = xor(d.decryptBlock(inputChunk), prev);
			
			System.arraycopy(plaintextChunk, 0, finalplaintext, i, 16);

			prev = inputChunk;
		}

		// Eliminate the padding
		finalplaintext = removePkcs5Padding(finalplaintext);

		return finalplaintext;
	}

	// Byte by byte xor operation.
	public byte[] xor(byte[] a, byte[] b) {
		byte[] ret = new byte[16];

		for (int i = 0; i < 16; i++)
			ret[i] = (byte) (a[i] ^ b[i]);

		return ret;
	}

	public byte[] addPkcs5Padding(byte[] input) {
		byte paddingLength = (byte) (16 - (input.length % 16));
		byte[] ret = new byte[input.length + paddingLength];

		System.arraycopy(input, 0, ret, 0, input.length);

		for (int i = input.length; i < ret.length; i++)
			ret[i] = paddingLength;

		return ret;
	}

	public byte[] removePkcs5Padding(byte[] input) {
		byte[] ret = new byte[input.length - input[input.length - 1]];

		System.arraycopy(input, 0, ret, 0, ret.length);

		return ret;
	}
}