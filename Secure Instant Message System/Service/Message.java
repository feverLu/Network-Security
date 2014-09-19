package Service;

import java.io.Serializable;

public class Message implements Serializable{
	public String TYPE;
	
	public String cookie;
	
	public byte[] ticket;
	
	public byte[] data;
	
	public String getType() {
		return TYPE;
	}
}
