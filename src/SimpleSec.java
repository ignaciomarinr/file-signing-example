import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;

import javax.crypto.KeyGenerator;

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

	private static void e(String sourceFile, String destinationFile) {
		byte[] srcFileBytes = null;
		try {
			srcFileBytes = Files.readAllBytes(Paths.get(sourceFile));
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
		
		// Encrypt the session key with the public key, using AES-CBC.
		secFile.encSessionKey = rsaLibrary.encrypt(sessionKey, getPk());
		
		// Sign the encrypted file and the encrypted session key with the private key.
		byte[] dataToSign = new byte[secFile.encFile.length + secFile.encSessionKey.length];
		System.arraycopy(secFile.encFile, 0, dataToSign, 0, secFile.encFile.length);
		System.arraycopy(secFile.encSessionKey, 0, dataToSign, secFile.encFile.length, secFile.encSessionKey.length);
		
		secFile.sign = rsaLibrary.sign(dataToSign, getSk());
		
		// Save in destinationFile.
		try (FileOutputStream fos = new FileOutputStream(destinationFile);
				ObjectOutputStream oos = new ObjectOutputStream(fos)) {
			oos.writeObject(secFile);
		} catch (IOException e) {
			System.err.println("Error - no posible escribir el fichero securizado en disco:");
			System.err.println(e.getMessage());
			System.exit(-1);
		}
	}

	private static void d(String sourceFile, String destinationFile) {
		// Read secured input file.
		SecureFile secFile = null;
		try (FileInputStream fis = new FileInputStream(sourceFile);
				ObjectInputStream ois = new ObjectInputStream(fis)) {
			secFile = (SecureFile) ois.readObject();
		} catch (ClassNotFoundException e) {
			System.err.println("Error - el fichero de entrada securizado no tiene el formato correcto:");
			System.err.println(e.getMessage());
			System.exit(-1);
		} catch (IOException e) {
			System.err.println("Error - no posible leer el fichero de entrada securizado:");
			System.err.println(e.getMessage());
			System.exit(-1);
		}
		
		// Verify the sign.
		byte[] dataToVerify = new byte[secFile.encFile.length + secFile.encSessionKey.length];
		System.arraycopy(secFile.encFile, 0, dataToVerify, 0, secFile.encFile.length);
		System.arraycopy(secFile.encSessionKey, 0, dataToVerify, secFile.encFile.length, secFile.encSessionKey.length);
		
		if (!rsaLibrary.verify(dataToVerify, secFile.sign, getPk())) {
			System.err.println("La firma del fichero securizado es errónea.");
			System.exit(-1);
		}
		
		// Decrypt the secured file with AES-CBC.
		byte[] dtsFileBytes = null;
		try {
			dtsFileBytes = symmetricCipher.decryptCBC(secFile.encFile,
					rsaLibrary.decrypt(secFile.encSessionKey, getSk()));
		} catch (Exception e) {
			System.err.println("Error al descifrar el fichero securizado con la clave de sesión:");
			System.err.println(e.getMessage());
			System.exit(-1);
		}
		
		// Save the decrypted secured file in destinationFile.
		try {
			Files.write(Paths.get(destinationFile), dtsFileBytes);
		} catch (IOException e) {
			System.err.println("Error - no posible escribir el fichero securizado descifrado en disco:");
			System.err.println(e.getMessage());
			System.exit(-1);
		}
	}

	private static PrivateKey getSk() {
		// Read encrypted private key.
		byte[] encSk = null;
		try (FileInputStream fis = new FileInputStream(privateKeyFile);
				ObjectInputStream ois = new ObjectInputStream(fis)) {
			encSk = (byte[]) ois.readObject();
		} catch (ClassNotFoundException e) {
			System.err.println("Error - el fichero de clave privada no tiene el formato correcto:");
			System.err.println(e.getMessage());
			System.exit(-1);
		} catch (IOException e) {
			System.err.println("Error - no posible leer el fichero de la clave privada:");
			System.err.println(e.getMessage());
			System.exit(-1);
		}
		
		// Decipher private key.
		byte[] decSk = null;
		try {
			decSk = symmetricCipher.decryptCBC(encSk, askSkPassword());
		} catch (Exception e) {
			System.err.println("Error al descifrar el fichero de la clave privada:");
			System.err.println(e.getMessage());
			System.exit(-1);
		}
		
		// Get PrivateKey object.
		PrivateKey sk = null;
		try (ByteArrayInputStream bis = new ByteArrayInputStream(decSk);
				ObjectInputStream ois = new ObjectInputStream(bis)) {
			sk = (PrivateKey) ois.readObject();
		} catch (ClassNotFoundException e) {
			System.err.println("Error - la clave privada descrifrada no tiene el formato correcto:");
			System.err.println(e.getMessage());
			System.exit(-1);
		} catch (IOException e) {
			System.err.println("Error - no posible leer la clave privada descifrada:");
			System.err.println(e.getMessage());
			System.exit(-1);
		}
		
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

	public static void main(String[] args) {
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