package Service;

import java.io.Serializable;
import java.net.InetAddress;
import java.sql.Date;

public class MessageDetail implements Serializable{
	public String userA;
	
	public String userB;
	
	public byte[] pwd;
	
	public byte[] gABModP;
	
	public byte[] KC;
	
	public byte[] c1;
	
	public int c2;
	
	public int c3;
	
	public InetAddress ip;
	
	public int port;
	
	public byte[] KAB;
	
	public byte[] ticket;
	
	public long expire;
}
