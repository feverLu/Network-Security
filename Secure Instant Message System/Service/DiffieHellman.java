package Service;

import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Properties;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import chatServer.ChatServer;

public class DiffieHellman {
	private final BigInteger modulus;
	
	private final BigInteger base;
	
	public DHParameterSpec dhSkipParamSpec;
	
	private KeyAgreement keyAgreement;
	
	public DiffieHellman() {
		Properties prop = ServiceMethods.loadProperties();
		modulus = new BigInteger(prop.getProperty("p"));
		base = new BigInteger(prop.getProperty("g"));
		dhSkipParamSpec = new DHParameterSpec(modulus, base);
	}	
	
	public byte[] genPublicKey() {
		try {
			KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
			keyPairGen.initialize(dhSkipParamSpec);
			KeyPair keyPair = keyPairGen.generateKeyPair();
			
			keyAgreement = KeyAgreement.getInstance("DH");
			keyAgreement.init(keyPair.getPrivate());
			byte[] encodedPubKey = keyPair.getPublic().getEncoded();
			
			return encodedPubKey;
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	public byte[] genSharedSecretKey(byte[] publicKey) {
		try {
			KeyFactory keyFac = KeyFactory.getInstance("DH");
			X509EncodedKeySpec x509keySpec = new X509EncodedKeySpec(publicKey);
			PublicKey oppositePulicKey = keyFac.generatePublic(x509keySpec);
			keyAgreement.doPhase(oppositePulicKey, true);
			
			return keyAgreement.generateSecret();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalStateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	public SecretKey genAESKey(byte[] oppositePublicKeyBytes) {
		try {
			KeyFactory keyFac = KeyFactory.getInstance("DH");
			X509EncodedKeySpec x509keySpec = new X509EncodedKeySpec(oppositePublicKeyBytes);
			PublicKey oppositePubKey = keyFac.generatePublic(x509keySpec);
			keyAgreement.doPhase(oppositePubKey, true);
			final byte[] sharedSecret = keyAgreement.generateSecret();
			SecretKey aesKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");
			
			return aesKey;
			
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalStateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
}
