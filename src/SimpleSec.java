import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Scanner;

import javax.xml.bind.DatatypeConverter;


public class SimpleSec {
	RSALibrary rsaLibrary = new RSALibrary();
	SymmetricCipher symmetricCipher = new SymmetricCipher();
	// String to hold the name of the private key file.
	public final String PRIVATE_KEY_FILE = "./private.key";
	public final String PUBLIC_KEY_FILE = "./public.key";
	
	public void g() throws Exception {
		//generate key pair
		rsaLibrary.generateKeys();
		//ask for password (will be used as AES key)s
		String pwd = askPassword();
		//Get private key 
		PrivateKey sk = null;
		try (FileInputStream fis = new FileInputStream(PRIVATE_KEY_FILE);
				ObjectInputStream ois = new ObjectInputStream(fis)) {
			sk = (PrivateKey) ois.readObject();
		}
		//Cipher SK with CBC
		byte[] ciphSK = symmetricCipher.encryptCBC(sk.getEncoded(),pwd.getBytes());
		System.out.println("Ciphertext (hex): " + DatatypeConverter.printHexBinary(ciphSK));
		//Guardar  en fichero la clave privada cifrada
		try (FileOutputStream fos = new FileOutputStream(PRIVATE_KEY_FILE);
				ObjectOutputStream oos = new ObjectOutputStream(fos)) {
			oos.writeObject(ciphSK);
		}
		
	}
	
	public void e(String srcFile, String destFile) throws Exception{
		
		// Read the public key. Will be used for encrypting
		PublicKey pk = getPK();
		
		//get sourceFile
		byte[] srcBytes = null;
		try (FileInputStream fis = new FileInputStream(srcFile);
				ObjectInputStream ois = new ObjectInputStream(fis)) {
			srcBytes = (byte[]) (ois.readObject());
		}
		//file encryption with the public key 
		byte[] encryptedSrcFile = RSALibrary.encrypt(srcBytes, pk);
		
		//For signing we need the encryptedSrcFile hash and sign it with our private key:
		
		PrivateKey sk = decryptSK();
		
		//Sign with sk
		byte[] encryptedSrcFileSigned = RSALibrary.sign(encryptedSrcFile,sk);
		//EncryptedSrcFile & encryptedSrcFileSigned concatenation
		byte[] encryptedAndSignedSrc = null;
		System.arraycopy(encryptedSrcFile, 0, encryptedAndSignedSrc, 0, encryptedSrcFile.length);
		System.arraycopy(encryptedSrcFileSigned, 0, encryptedAndSignedSrc, encryptedSrcFile.length, encryptedSrcFileSigned.length);
		//Save in file
		try (FileOutputStream fos = new FileOutputStream(destFile);
				ObjectOutputStream oos = new ObjectOutputStream(fos)) {
			oos.writeObject(encryptedSrcFileSigned);
		}
		
	}
	
	public void d(String srcFile, String destFile) throws Exception{
		//Read srcFile
		byte[] srcBytes = null;
		try (FileInputStream fis = new FileInputStream(srcFile);
				ObjectInputStream ois = new ObjectInputStream(fis)) {
			srcBytes = (byte[]) (ois.readObject());
		}
		//Last 128 bytes are the signature
		byte[] cipheredText = null;
		byte[] sig = null;
		System.arraycopy(srcBytes, 0, cipheredText, 0, srcBytes.length-128);
		System.arraycopy(srcBytes, srcBytes.length-128, sig, 0, 128);
		
		//get Sk and sk
		PrivateKey sk = decryptSK();
		PublicKey pk = getPK();
		//Verify signature
		RSALibrary.verify(cipheredText,sig,pk);
		//Decipher cipheredText
		byte[] decryptedText = RSALibrary.decrypt(cipheredText,sk);
		//Write in file
		try (FileOutputStream fos = new FileOutputStream(destFile);
				ObjectOutputStream oos = new ObjectOutputStream(fos)) {
			oos.writeObject(decryptedText);
		}

	}
	
	private PrivateKey decryptSK() throws Exception {
		//Ask for password
		String pwd = askPassword();
		//Get encrypted privateKey
		byte[] encryptedSK = null;
		try (FileInputStream fis = new FileInputStream(PRIVATE_KEY_FILE);
				ObjectInputStream ois = new ObjectInputStream(fis)) {
			encryptedSK = (byte[]) (ois.readObject());
		}
		//Decipher PrivateKey
		byte[] decryptedSK = symmetricCipher.decryptCBC(encryptedSK, pwd.getBytes());
		//PrivateKey from bytes
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PrivateKey sk = kf.generatePrivate(new PKCS8EncodedKeySpec(decryptedSK));
		return sk;
	}
	
	private PublicKey getPK() throws Exception {
		PublicKey pk = null;

		try (FileInputStream fis = new FileInputStream(PUBLIC_KEY_FILE);
				ObjectInputStream ois = new ObjectInputStream(fis)) {
			pk = (PublicKey) ois.readObject();
		}
		return pk;
	}
	private String askPassword() {
		Scanner reader = new Scanner(System.in);  // Reading from System.in
		System.out.println("Introduzca contraseña: ");
		String n = reader.nextLine(); // Scans the next token of the input as an int.
		//once finished
		reader.close();
		return n;
	}
	
	public static void main(String[] args) {
			
	}
}