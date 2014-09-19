package nc_ps2;

import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

/**
 * 
 * EncryptionDecryption provides methods of different steps in encrypting and decrypting files
 * 
 * @author <a href="mailto:lu.b@husky.neu.edu">Binbin Lu</a>
 *
 */
public class EncryptionDecryption {
	public static final int AES_Key_Size = 128;
	
	public static final String RSA = "RSA";
	
	public static final String AES = "AES";
	
	public static final String SHA256WITHRSA = "SHA256withRSA";
	
	Cipher rsaCipher, aesCipher;
	SecretKeySpec aesKeySpec;
	byte[] aesKey;
	
	/**
	 *  constructor: create shared RSA key cipher and shared AES key cipher
	 */
	public EncryptionDecryption() {
		try {
			rsaCipher =  Cipher.getInstance(RSA);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			System.out.println("failed to create RSA cipher.");
			e.printStackTrace();
		}
		try {
			aesCipher = Cipher.getInstance(AES);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			System.out.println("failed to create AES cipher.");
			e.printStackTrace();
		}
	} 
	
	public void generateSecretKey() throws NoSuchAlgorithmException {
		// generate aesKey
		KeyGenerator keyGenerator = KeyGenerator.getInstance(AES);
		keyGenerator.init(AES_Key_Size);
		SecretKey secretKey = keyGenerator.generateKey();
		aesKey = secretKey.getEncoded();
		aesKeySpec = new SecretKeySpec(aesKey, AES);
	}
	
	public  PublicKey readPublicKey(byte[] encodedKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
		// get the public key for the given encoded key
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedKey);
		KeyFactory keyFactory = KeyFactory.getInstance(RSA);
		PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
		return publicKey;
	}
	
	public PrivateKey readPrivateKey(byte[] encodedKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
		// get the private key for the given encoded key
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedKey);
		KeyFactory keyFactory = KeyFactory.getInstance(RSA);
		PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
		return privateKey;
	}
	
	public byte[] saveSecretKey (PublicKey receiverPublicKey) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException  {
		// encrypt and store the secret key
		generateSecretKey();
		rsaCipher.init(Cipher.ENCRYPT_MODE, receiverPublicKey);	
		byte[] cipheredSecretKey = null;
		cipheredSecretKey = rsaCipher.doFinal(aesKey);
		
		return cipheredSecretKey;
	}
		
	public byte[] loadSecretKey(byte[] cipheredAESKey, PrivateKey receiverPrivateKey) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		// decrypt the AES Key
		rsaCipher.init(Cipher.DECRYPT_MODE, receiverPrivateKey);
		aesKey = rsaCipher.doFinal(cipheredAESKey);
		aesKeySpec = new SecretKeySpec(aesKey, AES);
		
		return aesKey;
	}
	
	public byte[] signFile(byte[] content, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException  {
		// sign the given file with the given private key
		Signature signature = Signature.getInstance(SHA256WITHRSA);
		signature.initSign(privateKey);
		signature.update(content);
        byte[] signatureBytes = signature.sign();
        
        return signatureBytes;
	}
	
	public boolean unSignFile(byte[] cipheredSignature, byte[] content, PublicKey senderPublicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		// verify the signature with the given text content
		Signature signature = Signature.getInstance(SHA256WITHRSA);
		signature.initVerify(senderPublicKey);
		signature.update(content);
		boolean isSignature = signature.verify(cipheredSignature);
		
		return isSignature;
	}
	
	public byte[] encrypt(byte[] content) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		// encrypt the given content with aeskey generated before
		aesCipher.init(Cipher.ENCRYPT_MODE, aesKeySpec);
		byte[] cipheredText = null;
		cipheredText = aesCipher.doFinal(content);
		
		return cipheredText;
	}
	
	public byte[] decrypt(byte[] cipheredText) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
		// decrypt the cipher with aeskey
		aesCipher.init(Cipher.DECRYPT_MODE, aesKeySpec);
		byte[] originalText = aesCipher.doFinal(cipheredText);
		
		return originalText;
	}
	
	public void writeFile (String path, byte[] content) throws IOException {
		FileOutputStream os = new FileOutputStream(path);
		os.write(content);
		os.close();
	}
	
	
	public byte[] readFile(String path) throws FileNotFoundException, IOException {
		File file = new File(path);
		byte[] content = new byte[(int) file.length()];
		new FileInputStream(file).read(content);
		return content;
	}
}
