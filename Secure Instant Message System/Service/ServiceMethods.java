package Service;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Properties;
import java.util.Random;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class ServiceMethods {

	public static byte[] readFully(InputStream input) throws IOException
	{
		int count = 0;  
        while (count == 0) {  
            count = input.available();  
        }  
        byte[] b = new byte[count];  
        input.read(b); 
        return b;

//	    byte[] buffer = new byte[4096];
//	    int bytesRead = -1;
//	    ByteArrayOutputStream output = new ByteArrayOutputStream();
//	    while ((bytesRead = input.read(buffer, 0, 4096)) != -1)
//	    {
//	    	System.out.print("byteStream read");
//	        output.write(buffer, 0, bytesRead);
//	    }
//	    System.out.println(Arrays.toString(output.toByteArray()));
//	    return output.toByteArray();
		
//		ByteArrayOutputStream baos = new ByteArrayOutputStream();
//	    byte[] buffer = new byte[1024];
//	    int length = 0;
//	    while ((length = input.read(buffer)) != -1) {
//	        baos.write(buffer, 0, length);
//	    }
//	    return baos.toByteArray();
	}
	
	public static Properties loadProperties() {
		Properties prop = new Properties();
		try {
			prop.load(new FileInputStream("resource/SIMS.properties"));
			return prop;
		} catch (FileNotFoundException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	public static byte[] getPwdHash(String pwd){
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			md.update(pwd.getBytes());
			byte[]  pwdDigest = md.digest();
//			StringBuffer sb = new StringBuffer();
//			for (int i=0; i<pwdDigest.length; i++) {
//				sb.append(Integer.toString((pwdDigest[i] & 0xff) + 0x100, 16).substring(1));
//			}
//			return sb.toString();
			return pwdDigest;
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	public static int genRandom() {
		Random rand = new Random(System.currentTimeMillis());
		return rand.nextInt(10000)+1;
	}
	
	public static byte[] generateSecretKey() {
		SecretKey aesKey = null;
		//Generate the AES Key
		try {
			//Create a new AES KeyGenerator
			KeyGenerator aesKeyGen = KeyGenerator.getInstance("AES");
			
			//Set size to 256 bits
			aesKeyGen.init(256, new SecureRandom());
			
			//Generate the key
			aesKey = aesKeyGen.generateKey();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return aesKey.getEncoded();
	}
}
