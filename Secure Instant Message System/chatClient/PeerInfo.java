package chatClient;

import java.net.InetAddress;

import Service.DiffieHellman;

public class PeerInfo {
	public InetAddress ip;
	
	public int port;
	
	public byte[] KAB;
	
	public byte[] iv;
	
	public int num;
	
	public DiffieHellman dh;
	
	public boolean authenticated = false;
}
