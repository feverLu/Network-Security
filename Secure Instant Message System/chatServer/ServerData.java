package chatServer;

import java.net.InetAddress;
import java.util.ArrayList;

import javax.crypto.SecretKey;

import chatClient.Clients;

public class ServerData {
	public String username;
	
	public String status; 
	
	public InetAddress ip;

	public int port;
	
	public byte[] iv;
	
	public byte[] aesKey;
	
	public long timestamp;
	
	public String getUsername() {
		return username;
	}
	
	public long getTimeStamp() {
		return timestamp;
	}
	
	public void setTimeStamp(long timestamp) {
		this.timestamp = timestamp;
	}
}
