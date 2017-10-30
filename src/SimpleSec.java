import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Scanner;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class SimpleSec {
	// Ciphers.
	private static final RSALibrary rsaLibrary = new RSALibrary();
	private static final SymmetricCipher symmetricCipher = new SymmetricCipher();

	// String to hold the name of the private key file.
	private static final String privateKeyFile = "./private.key";

	// String to hold name of the public key file.
	private static final String publicKeyFile = "./public.key";

	private static void g() {
		// Ask for password (will be used as AES key).
		byte[] pwd = askSkPassword();

		// Generate key pair.
		try {
			rsaLibrary.generateKeys();
		} catch (IOException e) {
			System.err.println("Error - no es posible escribir los ficheros de las claves en disco:");
			System.err.println(e.getMessage());
			System.exit(-1);
		}

		// Read the private key.
		byte[] skFileBytes = null;
		try {
			skFileBytes = Files.readAllBytes(Paths.get(privateKeyFile));
		} catch (IOException e) {
			System.err.println("Error - no es posible escribir los ficheros de las claves en disco:");
			System.err.println(e.getMessage());
			System.exit(-1);
		}

		// Encrypt the private key with AES-CBC.
		byte[] encSk = null;
		try {
			encSk = symmetricCipher.encryptCBC(skFileBytes, pwd);
		} catch (Exception e) {
			System.err.println("Error al cifrar la clave privada:");
			System.err.println(e.getMessage());
			System.exit(-1);
		}

		// Store the private key in the file privateKeyFile (overwriting previous clear
		// private key file).
		try (FileOutputStream fos = new FileOutputStream(privateKeyFile);
				ObjectOutputStream oos = new ObjectOutputStream(fos)) {
			oos.writeObject(encSk);
		} catch (IOException e) {
			System.err.println("Error - no posible escribir el fichero cifrado de la clave privada en disco:");
			System.err.println(e.getMessage());
			System.exit(-1);
		}
	}

	// TODO throws Exception.
	private static void e(String srcFile, String destFile) {
		byte[] srcFileBytes = null;
		try {
			srcFileBytes = Files.readAllBytes(Paths.get(srcFile));
		} catch (IOException e) {
			System.err.println("Error - no es posible leer el fichero de entrada:");
			System.err.println(e.getMessage());
			System.exit(-1);
		}
		
		SecureFile secFile = new SecureFile();
		byte[] sessionKey = getSessionKey();
		
		// Encrypt the source file with AES-CBC.
		try {
			secFile.encFile = symmetricCipher.encryptCBC(srcFileBytes, sessionKey);
		} catch (Exception e) {
			System.err.println("Error al cifrar el fichero de entrada con la clave de sesión:");
			System.err.println(e.getMessage());
			System.exit(-1);
		}
		
		// Read the public key. Will be used for encrypting the session key.
		PublicKey pk = getPk();

		/*
		// get sourceFile
		byte[] srcBytes = null;
		try (FileInputStream fis = new FileInputStream(srcFile); ObjectInputStream ois = new ObjectInputStream(fis)) {
			srcBytes = (byte[]) (ois.readObject());
		}
		// file encryption with the public key
		byte[] encryptedSrcFile = rsaLibrary.encrypt(srcBytes, pk);

		// For signing we need the encryptedSrcFile hash and sign it with our private
		// key:

		PrivateKey sk = getSk();

		// Sign with sk
		byte[] encryptedSrcFileSigned = rsaLibrary.sign(encryptedSrcFile, sk);
		// EncryptedSrcFile & encryptedSrcFileSigned concatenation
		byte[] encryptedAndSignedSrc = null;
		System.arraycopy(encryptedSrcFile, 0, encryptedAndSignedSrc, 0, encryptedSrcFile.length);
		System.arraycopy(encryptedSrcFileSigned, 0, encryptedAndSignedSrc, encryptedSrcFile.length,
				encryptedSrcFileSigned.length);
		// Save in file
		try (FileOutputStream fos = new FileOutputStream(destFile);
				ObjectOutputStream oos = new ObjectOutputStream(fos)) {
			oos.writeObject(encryptedSrcFileSigned);
		}
		*/
	}

	private static void d(String srcFile, String destFile) throws Exception {
		// Read srcFile
		byte[] srcBytes = null;
		try (FileInputStream fis = new FileInputStream(srcFile); ObjectInputStream ois = new ObjectInputStream(fis)) {
			srcBytes = (byte[]) (ois.readObject());
		}
		// Last 128 bytes are the signature
		byte[] cipheredText = null;
		byte[] sig = null;
		System.arraycopy(srcBytes, 0, cipheredText, 0, srcBytes.length - 128);
		System.arraycopy(srcBytes, srcBytes.length - 128, sig, 0, 128);

		// get Sk and sk
		PrivateKey sk = getSk();
		PublicKey pk = getPk();
		// Verify signature
		rsaLibrary.verify(cipheredText, sig, pk);
		// Decipher cipheredText
		byte[] decryptedText = rsaLibrary.decrypt(cipheredText, sk);
		// Write in file
		try (FileOutputStream fos = new FileOutputStream(destFile);
				ObjectOutputStream oos = new ObjectOutputStream(fos)) {
			oos.writeObject(decryptedText);
		}

	}

	private static PrivateKey getSk() throws Exception {
		// Ask for password
		byte[] pwd = askSkPassword();
		// Get encrypted privateKey
		byte[] encryptedSK = null;
		try (FileInputStream fis = new FileInputStream(privateKeyFile);
				ObjectInputStream ois = new ObjectInputStream(fis)) {
			encryptedSK = (byte[]) (ois.readObject());
		}
		// Decipher PrivateKey
		byte[] decryptedSK = symmetricCipher.decryptCBC(encryptedSK, pwd);
		// PrivateKey from bytes
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PrivateKey sk = kf.generatePrivate(new PKCS8EncodedKeySpec(decryptedSK));
		return sk;
	}

	private static PublicKey getPk() {
		PublicKey pk = null;
		
		try (FileInputStream fis = new FileInputStream(publicKeyFile);
				ObjectInputStream ois = new ObjectInputStream(fis)) {
			pk = (PublicKey) ois.readObject();
		} catch (ClassNotFoundException e) {
			System.err.println("Error - el fichero de clave pública no tiene el formato correcto:");
			System.err.println(e.getMessage());
			System.exit(-1);
		} catch (IOException e) {
			System.err.println("Error - no posible leer el fichero de la clave pública:");
			System.err.println(e.getMessage());
			System.exit(-1);
		}
		
		return pk;
	}
	
	private static byte[] getSessionKey() {
		KeyGenerator kg = null;

		try {
			kg = KeyGenerator.getInstance("AES");
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Error - no es posible obtener el algoritmo AES para generar una clave de sesión:");
			System.err.println(e.getMessage());
			System.exit(-1);
		}

		kg.init(128);

		return kg.generateKey().getEncoded();
	}

	private static byte[] askSkPassword() {
		try (Scanner inScanner = new Scanner(System.in)) {
			byte[] pwd;

			do {
				System.out.print("Introduzca la contraseña de la clave privada: ");

				try {
					pwd = inScanner.nextLine().getBytes("UTF-8");
				} catch (UnsupportedEncodingException e) {
					System.err.println("Error - la contraseña debe poderse codificar en UTF-8:");
					System.err.println(e.getMessage());
					pwd = new byte[0];
					continue;
				}

				if (pwd.length != 16)
					System.err.println("Error: La contraseña debe ocupar 16 bytes en UTF-8");
			} while (pwd.length != 16);

			return pwd;
		}
	}

	// TODO throws Exception.
	public static void main(String[] args) throws Exception{
		// Arguments.
		// TODO check paths formats.
		String command = args.length >= 1 ? args[0] : "g",
				sourceFile = args.length >= 2 ? args[1] : "in.txt",
				destinationFile = args.length >= 3 ? args[2] : "out.txt";

		switch (command) {
			case "g":
				g();
				break;
				
			case "e":
				e(sourceFile, destinationFile);
				break;
				
			case "d":
				d(sourceFile, destinationFile);
				break;
	
			default:
				System.err.println("Usage: java -jar SimpleSec.jar g|e|d [sourceFile] [destinationFile]");
				break;
		}
	}
}