import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
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
		} catch (Exception e) {
			exception("no es posible generar los ficheros de las claves pública y privada", e);
		}

		// Read the private key.
		byte[] skFileBytes = null;
		try {
			skFileBytes = Files.readAllBytes(Paths.get(privateKeyFile));
		} catch (Exception e) {
			exception("no es posible leer el fichero de la clave privada", e);
		}

		// Encrypt the private key with AES-CBC.
		byte[] encSk = null;
		try {
			encSk = symmetricCipher.encryptCBC(skFileBytes, pwd);
		} catch (Exception e) {
			exception("no se puede cifrar la clave privada", e);
		}

		// Store the private key in the file privateKeyFile (overwriting previous clear
		// private key file).
		try (FileOutputStream fos = new FileOutputStream(privateKeyFile);
				ObjectOutputStream oos = new ObjectOutputStream(fos)) {
			oos.writeObject(encSk);
		} catch (IOException e) {
			exception("no posible escribir el fichero cifrado de la clave privada en disco", e);
		}
		
		System.out.println("Generación de claves finalizada.");
	}

	private static void e(String sourceFile, String destinationFile) {
		byte[] srcFileBytes = null;
		try {
			srcFileBytes = Files.readAllBytes(Paths.get(sourceFile));
		} catch (Exception e) {
			exception("no es posible leer el fichero de entrada", e);
		}
		
		SecureFile secFile = new SecureFile();
		byte[] sessionKey = getSessionKey();
		
		// Encrypt the source file with AES-CBC.
		try {
			secFile.encFile = symmetricCipher.encryptCBC(srcFileBytes, sessionKey);
		} catch (Exception e) {
			exception("no se puede cifrar el fichero de entrada con la clave de sesión", e);
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
		} catch (Exception e) {
			exception("no posible escribir el fichero securizado en disco", e);
		}
		
		System.out.println("Archivo cifrado con éxito.");
	}

	private static void d(String sourceFile, String destinationFile) {
		// Read secured input file.
		SecureFile secFile = null;
		try (FileInputStream fis = new FileInputStream(sourceFile);
				ObjectInputStream ois = new ObjectInputStream(fis)) {
			secFile = (SecureFile) ois.readObject();
		} catch (Exception e) {
			exception("no se puede leer el fichero de entrada securizado", e);
		}
		
		// Verify the sign.
		byte[] dataToVerify = new byte[secFile.encFile.length + secFile.encSessionKey.length];
		System.arraycopy(secFile.encFile, 0, dataToVerify, 0, secFile.encFile.length);
		System.arraycopy(secFile.encSessionKey, 0, dataToVerify, secFile.encFile.length, secFile.encSessionKey.length);
		
		if (!rsaLibrary.verify(dataToVerify, secFile.sign, getPk()))
			exception("la firma del fichero securizado es errónea");
		
		// Decrypt the secured file with AES-CBC.
		byte[] dtsFileBytes = null;
		try {
			dtsFileBytes = symmetricCipher.decryptCBC(secFile.encFile,
					rsaLibrary.decrypt(secFile.encSessionKey, getSk()));
		} catch (Exception e) {
			exception("no se puede descifrar el fichero securizado con la clave de sesión", e);
		}
		
		// Save the decrypted secured file in destinationFile.
		try {
			Files.write(Paths.get(destinationFile), dtsFileBytes);
		} catch (Exception e) {
			exception("no posible escribir el fichero securizado descifrado en disco", e);
		}
		
		System.out.println("Archivo descifrado con éxito.");
	}

	private static PrivateKey getSk() {
		// Read encrypted private key.
		byte[] encSk = null;
		try (FileInputStream fis = new FileInputStream(privateKeyFile);
				ObjectInputStream ois = new ObjectInputStream(fis)) {
			encSk = (byte[]) ois.readObject();
		} catch (Exception e) {
			exception("no se puede leer el fichero con la clave privada cifrada", e);
		}
		
		// Decipher private key.
		byte[] decSk = null;
		try {
			decSk = symmetricCipher.decryptCBC(encSk, askSkPassword());
		} catch (Exception e) {
			exception("no se puede descifrar el fichero de la clave privada", e);
		}
		
		// Get PrivateKey object.
		PrivateKey sk = null;
		try (ByteArrayInputStream bis = new ByteArrayInputStream(decSk);
				ObjectInputStream ois = new ObjectInputStream(bis)) {
			sk = (PrivateKey) ois.readObject();
		} catch (Exception e) {
			exception("la clave privada descrifrada no tiene el formato correcto", e);
		}
		
		return sk;
	}

	private static PublicKey getPk() {
		PublicKey pk = null;
		
		try (FileInputStream fis = new FileInputStream(publicKeyFile);
				ObjectInputStream ois = new ObjectInputStream(fis)) {
			pk = (PublicKey) ois.readObject();
		} catch (Exception e) {
			exception("no se puede leer el fichero de la clave pública", e);
		}
		
		return pk;
	}
	
	private static byte[] getSessionKey() {
		KeyGenerator kg = null;

		try {
			kg = KeyGenerator.getInstance("AES");
		} catch (Exception e) {
			exception("no es posible obtener el algoritmo AES para generar una clave de sesión", e);
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
				} catch (Exception e) {
					exception("la contraseña debe poderse codificar en UTF-8", e, false);
					pwd = new byte[0];
					continue;
				}

				if (pwd.length != 16)
					exception("la contraseña debe ocupar 16 bytes en UTF-8", null, false);
			} while (pwd.length != 16);
			
			return pwd;
		}
	}
	
	private static void exception(String msg) {
		exception(msg, null, true);
	}
	
	private static void exception(String msg, Exception exc) {
		exception(msg, exc, true);
	}
	
	private static void exception(String msg, Exception exc, boolean exit) {
		System.err.print("Error - " + msg);
		
		if (exc != null)
			System.err.println(":\n" + exc.getMessage());
		else
			System.err.println(".");
		
		System.err.flush();
		System.out.flush();
		
		if (exit)
			System.exit(msg.hashCode());
	}

	public static void main(String[] args) {
		// Arguments.
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
				System.err.println("Uso: java -jar SimpleSec.jar g|e|d [sourceFile] [destinationFile]");
				break;
		}
	}
}