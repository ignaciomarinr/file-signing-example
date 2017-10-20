import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import javax.crypto.Cipher;

public class RSALibrary {
	// String to hold name of the encryption algorithm.
	public final String ALGORITHM = "RSA";

	// String to hold the name of the private key file.
	public final String PRIVATE_KEY_FILE = "./private.key";

	// String to hold name of the public key file.
	public final String PUBLIC_KEY_FILE = "./public.key";

	/***********************************************************************************/
	/* Generates an RSA key pair (a public and a private key) of 1024 bits length. */
	/* Stores the keys in the files defined by PUBLIC_KEY_FILE and PRIVATE_KEY_FILE. */
	/* Throws IOException. */
	/***********************************************************************************/
	public void generateKeys() throws IOException {
		try {
			final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
			keyGen.initialize(1024);

			// Use KeyGen to generate a public and a private key.
			KeyPair kp = keyGen.generateKeyPair();

			// Store the public key in the file PUBLIC_KEY_FILE.
			PublicKey pk = kp.getPublic();
			try (FileOutputStream fos = new FileOutputStream(PUBLIC_KEY_FILE);
					ObjectOutputStream oos = new ObjectOutputStream(fos)) {
				oos.writeObject(pk);
			}

			// Store the private key in the file PRIVATE_KEY_FILE.
			PrivateKey sk = kp.getPrivate();
			try (FileOutputStream fos = new FileOutputStream(PRIVATE_KEY_FILE);
					ObjectOutputStream oos = new ObjectOutputStream(fos)) {
				oos.writeObject(sk);
			}
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Exception: " + e.getMessage());
			System.exit(-1);
		}
	}

	/***********************************************************************************/
	/* Encrypts a plaintext using an RSA public key. */
	/* Arguments: the plaintext and the RSA public key. */
	/* Returns a byte array with the ciphertext. */
	/***********************************************************************************/
	public byte[] encrypt(byte[] plaintext, PublicKey key) {
		byte[] ciphertext = null;

		try {
			// Gets an RSA cipher object.
			final Cipher cipher = Cipher.getInstance(ALGORITHM);

			// Initialize the cipher object and use it to encrypt the plaintext.
			cipher.init(Cipher.ENCRYPT_MODE, key);
			ciphertext = cipher.doFinal(plaintext);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return ciphertext;
	}

	/***********************************************************************************/
	/* Decrypts a ciphertext using an RSA private key. */
	/* Arguments: the ciphertext and the RSA private key. */
	/* Returns a byte array with the plaintext. */
	/***********************************************************************************/
	public byte[] decrypt(byte[] ciphertext, PrivateKey key) {
		byte[] plaintext = null;

		try {
			// Gets an RSA cipher object.
			final Cipher cipher = Cipher.getInstance(ALGORITHM);

			// Initialize the cipher object and use it to decrypt the ciphertext.
			cipher.init(Cipher.DECRYPT_MODE, key);
			plaintext = cipher.doFinal(ciphertext);
		} catch (Exception ex) {
			ex.printStackTrace();
		}

		return plaintext;
	}

	/***********************************************************************************/
	/* Signs a plaintext using an RSA private key. */
	/* Arguments: the plaintext and the RSA private key. */
	/* Returns a byte array with the signature. */
	/***********************************************************************************/
	public byte[] sign(byte[] plaintext, PrivateKey key) {
		byte[] signedInfo = null;

		try {
			// Gets a Signature object.
			Signature signature = Signature.getInstance("SHA1withRSA");

			// Initialize the signature object with the private key.
			signature.initSign(key);

			// Set plaintext as the bytes to be signed.
			signature.update(plaintext);

			// Sign the plaintext and obtain the signature (signedInfo).
			signedInfo = signature.sign();
		} catch (Exception ex) {
			ex.printStackTrace();
		}

		return signedInfo;
	}

	/***********************************************************************************/
	/* Verifies a signature over a plaintext */
    /* Arguments: the plaintext, the signature to be verified (signed) 
    /* and the RSA public key */
    /* Returns TRUE if the signature was verified, false if not */
	/***********************************************************************************/
	public boolean verify(byte[] plaintext, byte[] signed, PublicKey key) {
		boolean result = false;

		try {
			// Gets a Signature object.
			Signature signature = Signature.getInstance("SHA1withRSA");

			// Initialize the signature object with the public key.
			signature.initVerify(key);

			// Set plaintext as the bytes to be verified.
			signature.update(plaintext);

			// Verify the signature (signed). Store the outcome in the boolean result.
			result = signature.verify(signed);
		} catch (Exception ex) {
			ex.printStackTrace();
		}

		return result;
	}
}