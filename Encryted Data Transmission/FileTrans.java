package nc_ps2;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * 
 * FileTrans is used to handle encryption and decryption
 * 
 * @author <a href="mailto:lu.b@husky.neu.edu">Binbin Lu</a>
 *
 */
public class FileTrans {
	public static final int AES_Key_Size = 128;
	
	public static final String RSA = "RSA";
	
	public static final String AES = "AES";
	
	public static final String SHA256WITHRSA = "SHA256withRSA";
	
	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, FileNotFoundException, IOException, InvalidKeySpecException, InvalidKeyException, SignatureException, IllegalBlockSizeException, BadPaddingException {
		if (args.length != 5) {
			System.err.println("Encrytion: -e destination_public_key_filename sender_private_key_filename\n\t\t"
										   + "input_plaintext_file output_ciphertext_file\n"
							+  "Decryption: -d destination_private_key_filename sender_public_key_filename\n\t\t"
											+ "input_ciphertext_file output_plaintext_file");
			System.exit(1);
		}
		
		String isEncryption = args[0];

		if (isEncryption.equals("-e")) {
			final String RECEIVER_PUBLIC = args[1];
			final String SENDER_PRIVATE = args[2];
			final String INPUT_PLAIN_TEXT = args[3];
			final String CIPHER_TEXT = args[4];
			
			/**
			 *  this is the encryption part
			 *  setp1: get the plain text
			 *  step2: get the sender's private key
			 *  step3: sign the file with sender's private key and the plain text
			 *  step4: encrypt the aesKey with receiver's public key using RSA algorithm
			 *  step5: encrypt the plain text using aesKey 
			 *  step6: record the length of encrypted signature, aesKey and content to be sent in the same file
			 *  step7: write encrypted text into file to be sent
			 */
			EncryptionDecryption encryption = new EncryptionDecryption();
			byte[] content = encryption.readFile(INPUT_PLAIN_TEXT);

			byte[] senderEncodedPrivateKey = encryption.readFile(SENDER_PRIVATE);
			System.out.println(senderEncodedPrivateKey);
			PrivateKey senderPrivateKey = encryption.readPrivateKey(senderEncodedPrivateKey);

			byte[] signature = encryption.signFile(content, senderPrivateKey);

			byte[] receiverEncodedPublicKey = encryption.readFile(RECEIVER_PUBLIC);
			PublicKey receiverPublicKey = encryption.readPublicKey(receiverEncodedPublicKey);
			byte[] cipheredAESKey = encryption.saveSecretKey(receiverPublicKey);
			
			byte [] cipherText = encryption.encrypt(content);
			
			int sigLen = signature.length;
			int cipheredAESKeyLen = cipheredAESKey.length;
			int cipheredTextLen = cipherText.length;
			int offset = 0;
			
			/**
			 * the encrypted file contains with the order: signature length, signature, aesKey length, aesKey, content length, content
			 * cipherContent is used to add them together with the given order
			 */
			byte[] cipherContent = new byte[sigLen + cipheredAESKeyLen + cipheredTextLen + 12];
			System.arraycopy(intToByte(sigLen), 0, cipherContent, offset, 4);
			offset = offset + 4;
			System.arraycopy(signature, 0, cipherContent, offset, sigLen);
			offset = offset + sigLen;
			System.arraycopy(intToByte(cipheredAESKeyLen), 0, cipherContent, offset, 4);
			offset = offset + 4;
			System.arraycopy(cipheredAESKey, 0, cipherContent, offset, cipheredAESKeyLen);
			offset = offset + cipheredAESKeyLen;
			System.arraycopy(intToByte(cipheredTextLen), 0, cipherContent, offset, 4);
			offset = offset + 4;
			System.arraycopy(cipherText, 0, cipherContent, offset, cipheredTextLen);
			
			encryption.writeFile(CIPHER_TEXT, cipherContent);
			
		} else if (isEncryption.equals("-d")){
			final String RECEIVER_PRIVATE = args[1];
			final String SENDER_PUBLIC = args[2];
			final String CIPHER_TEXT = args[3];
			final String OUTPUT_PLAIN_TEXT = args[4];
			
			/**
			 *  this is the decryption part
			 *  setp1: get the first 4 bytes of the signature length
			 *  step2: get the sender's signature according to the signature length
			 *  setp3: get the following 4 bytes of the aesKey length
			 *  step4: get the shared aesKey according to the aesKey length and decode with receiver's private key
			 *  setp5: get the following 4 bytes of the cipher length
			 *  step6: get the cipher according to the signature length and decode with shared aesKey
			 *  step7: verify sender's signature with decrypted plain text and sender's public key
			 *  step8: write decrypted text into file if the signature is right
			 */
			EncryptionDecryption decryption = new EncryptionDecryption();
			byte[] cipher = decryption.readFile(CIPHER_TEXT);
			int sigLen = byteArrayToInt(Arrays.copyOfRange(cipher, 0, 4));
			int offset = 4;
			byte[] signature = Arrays.copyOfRange(cipher, offset, sigLen + offset);
			offset = offset + sigLen;
			
			int cipheredAESKeyLen = byteArrayToInt(Arrays.copyOfRange(cipher, offset, offset + 4));
			offset = offset + 4;
			byte[] cipheredAESKey = Arrays.copyOfRange(cipher, offset, cipheredAESKeyLen + offset);
			offset = offset + cipheredAESKeyLen;
			
			int cipheredTextLen = byteArrayToInt(Arrays.copyOfRange(cipher, offset, offset + 4));
			offset = offset + 4;
			byte[] cipheredText = Arrays.copyOfRange(cipher, offset, cipheredTextLen + offset);
			
			byte[] receiverEncodedPrivateKey = decryption.readFile(RECEIVER_PRIVATE);
			PrivateKey receiverPrivateKey = decryption.readPrivateKey(receiverEncodedPrivateKey);
			byte[] aesKey = decryption.loadSecretKey(cipheredAESKey, receiverPrivateKey);
			
			byte[] originalText = decryption.decrypt(cipheredText);
			
			byte[] senderEncodedPublicKey = decryption.readFile(SENDER_PUBLIC);
			PublicKey senderPublicKey = decryption.readPublicKey(senderEncodedPublicKey);
			boolean isRightSignature = decryption.unSignFile(signature, originalText, senderPublicKey);
			
			if (isRightSignature) {
				System.out.println("the signature is right");
				decryption.writeFile(OUTPUT_PLAIN_TEXT, originalText);
			} else {
				System.out.println("the signature is wrong");
			}
		}
	}
	
	// convert int type to byte
	public static byte[] intToByte (int i) {
		byte[] result = new byte[4];  
		result[0] = (byte)((i >> 24) & 0xFF);
		result[1] = (byte)((i >> 16) & 0xFF);
		result[2] = (byte)((i >> 8) & 0xFF);
		result[3] = (byte)(i & 0xFF);
		return result;
		}
	
	// convert byte into int type
	public static int byteArrayToInt(byte[] bytes) {
		int value= 0;
		for (int i = 0; i < 4; i++) {
			int shift= (4 - 1 - i) * 8;
		 	value +=(bytes[i] & 0x000000FF) << shift;
		}
		return value;
	}

}
