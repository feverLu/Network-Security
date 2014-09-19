package nc_ps2;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class DigitalSignature {
	public static final String RSA = "RSA";
	
	public static final String PATH = "G:\\Network Security\\ps2";
	
	public static final String SENDER_PUBLIC = "/sender_public.key";
	
	public static final String SENDER_PRIVATE = "/sender_private.key";
	
	public static final String INPUT_PLAIN_TEXT = "/input_plain.txt";
	
	public static final String CIPHER_TEXT = "/message_cipher.txt";
	
	public static final String OUTPUT_PLAIN_TEXT = "/output_plain.txt";
	
	public static final String SHA256WITHRSA = "SHA256withRSA";
	
	public static final int SIGNATURE_LENGTH = 128;
	
	
	
	@SuppressWarnings("resource")
	public byte[] signFile() throws FileNotFoundException, IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
		// read sender private key to be used to sign the file
		File senderPrivateKeyFile = new File(PATH + SENDER_PRIVATE);
		byte[] encodedKey = new byte[(int)senderPrivateKeyFile.length()];
		new FileInputStream(senderPrivateKeyFile).read(encodedKey);
		
		// get the sender's private key
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedKey);
		KeyFactory keyFactory = KeyFactory.getInstance(RSA);
		PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
		
		// read the plain text
		File PlainTextFile = new File(PATH + INPUT_PLAIN_TEXT);
        BufferedInputStream bis = new BufferedInputStream(new FileInputStream(PlainTextFile));
        byte[] content = new byte[(int) PlainTextFile.length()];
        bis.read(content);
		
        // hash the palin text, and sign it with the sender's private key
		Signature signature = Signature.getInstance(SHA256WITHRSA);
		signature.initSign(privateKey);
		signature.update(content);
        byte[] signatureBytes = signature.sign();

        return signatureBytes;
//        // append to the cipher text
//        FileOutputStream fos = new FileOutputStream(PATH + CIPHER_TEXT);
//        fos.write(signatureBytes);
//        fos.close();
	}
	
	@SuppressWarnings("resource")
	public boolean unSignFile() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
		// read sender's public key
		File senderPublicKeyFile = new File(PATH + SENDER_PUBLIC);
		byte[] encodedKey = new byte[(int)senderPublicKeyFile.length()];
		new FileInputStream(senderPublicKeyFile).read(encodedKey);
		
		// get sender's public key
		X509EncodedKeySpec publlicKeySpec = new X509EncodedKeySpec(encodedKey);
		KeyFactory keyFactory = KeyFactory.getInstance(RSA);
		PublicKey publicKey = keyFactory.generatePublic(publlicKeySpec);
		
		// get the ciphered signature
		File cipherTextFile = new File(PATH + CIPHER_TEXT);
		BufferedInputStream bis = new BufferedInputStream(new FileInputStream(cipherTextFile));
		byte [] signatureBytes = new byte[SIGNATURE_LENGTH];
		System.out.println("cipher test length: " + cipherTextFile.length());
		bis.read(signatureBytes, 0, SIGNATURE_LENGTH);
		
		// get the decrypt plain text 
		File PlainTextFile = new File(PATH + OUTPUT_PLAIN_TEXT);
        BufferedInputStream signatureBis = new BufferedInputStream(new FileInputStream(PlainTextFile));
        byte[] content = new byte[(int) PlainTextFile.length()];
        signatureBis.read(content);
		
		// retrieve the signature
		Signature signature = Signature.getInstance(SHA256WITHRSA);
		signature.initVerify(publicKey);
		signature.update(content);
		boolean isSignature = signature.verify(signatureBytes);
		
		return isSignature;
	}

}
