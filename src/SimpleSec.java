import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.security.PrivateKey;
import java.util.Scanner;

import javax.xml.bind.DatatypeConverter;

public class SimpleSec {
	RSALibrary rsaLibrary = new RSALibrary();
	SymmetricCipher symmetricCipher = new SymmetricCipher();
	// String to hold the name of the private key file.
	public final String PRIVATE_KEY_FILE = "./private.key";
	
	public void g() throws Exception {
		rsaLibrary.generateKeys();
		String pwd = askPassword();
		//Get private key 
		PrivateKey sk = null;
		try (FileInputStream fis = new FileInputStream(PRIVATE_KEY_FILE);
				ObjectInputStream ois = new ObjectInputStream(fis)) {
			sk = (PrivateKey) ois.readObject();
		}
		//Cipher SK with CBC
		byte[] ciphSK = symmetricCipher.encryptCBC(pwd.getBytes(), sk.getEncoded());
		System.out.println("Ciphertext (hex): " + DatatypeConverter.printHexBinary(ciphSK));
		//TODO: guardar srcFile en fichero
	}
	
	public void e(String srcFile, String destFile) throws Exception{
		//get sourceFile
		PrivateKey ciphSK = null;
		try (FileInputStream fis = new FileInputStream(srcFile);
				ObjectInputStream ois = new ObjectInputStream(fis)) {
			ciphSK = (PrivateKey) ois.readObject();
		}
		//ask for password
		String pwd = askPassword();
		//decipher SK
		byte[] deciphSK = symmetricCipher.decryptCBC(ciphSK.getEncoded(), pwd.getBytes());
		//TODO: no se qué hay que firmar, continuar
		//sign
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