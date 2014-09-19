package chatServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Properties;

import Service.DiffieHellman;
import Service.EncryptDecrypt;
import Service.Message;
import Service.MessageDetail;
import Service.SerializeObject;
import Service.ServiceMethods;

public class Server {
	
	public InetAddress serverIpAdd;
	public int serverPort;
	
	public byte[] setCookie(byte[] clientAdd) {
		try {
			MessageDigest cookie = MessageDigest.getInstance("SHA-256");
			
			Date date = new Date();
			SimpleDateFormat sdf = new SimpleDateFormat("MM/dd/yyyy h:mm:ss a");
			String timestamp = sdf.format(date);

			StringBuilder cookieInfo = new StringBuilder(new String(clientAdd));
			cookieInfo.append(", ");
			cookieInfo.append(timestamp);
			
			cookie.update(cookieInfo.toString().getBytes());
			return cookie.digest();
			
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	public void replyCookie(Socket socket) {
		InetAddress clientAdd = socket.getInetAddress();
		byte[] cookie = setCookie(clientAdd.getAddress());
		
		ServerData serverData = new ServerData();
		serverData.ip = clientAdd;
		serverData.timestamp = System.currentTimeMillis()+(1000*2);
		String cookieStr = new String(cookie);
		ChatServer.database.put(cookieStr, serverData); 
		
		Message message = new Message();
		message.TYPE = "REPLY COOKIE";
		message.cookie = cookieStr;
		SerializeObject so = new SerializeObject();
		byte[] messagebyte = so.serialize(message);
		
		OutputStream outStream;
		try {
			outStream = socket.getOutputStream();
			outStream.write(messagebyte);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	/**
	 * Authenticate the client with the password pair
	 * @param client Clients object
	 * @param pwd hash of the password typed by the client
	 * @return true if the client username matches the password, return false if it doesn't exists in 
	 * user list
	 */
	public int authenticate(Socket socket, Message message) {
		String receivedCookie = message.cookie;
		if (!ChatServer.database.containsKey(receivedCookie)) {
			System.out.print("Error: cookie does not exit in our database");
			return 1;
		}
		
		ServerData serverData = ChatServer.database.get(receivedCookie);
		InetAddress ip = socket.getInetAddress();
		if (!ip.equals(serverData.ip)) {
			System.out.println("Error: ip address does not  correspond to the cookie");
			return 2;
		}
		
		EncryptDecrypt ed = new EncryptDecrypt();
		SerializeObject so = new SerializeObject();
		MessageDetail secondMessageDetail = (MessageDetail) so.deserialize(message.data);
		
		String username = secondMessageDetail.userA;
		if (getUserInfoData(username) != null) {
			ChatServer.database.remove(receivedCookie);
			System.out.print("Error: user already online");
			return 6;
		}
		byte[] receivedPwd = ed.decryptPrivate(secondMessageDetail.pwd, "server");
		StringBuffer sb = new StringBuffer();
		for (int i=0; i<receivedPwd.length; i++) {
			sb.append(Integer.toString((receivedPwd[i] & 0xff) + 0x100, 16).substring(1));
		}
		String receivedPwdStr = sb.toString();
		
		Properties prop = ServiceMethods.loadProperties();
		String pwd = prop.getProperty(username);
		if (!receivedPwdStr.equals(pwd)) {
			ChatServer.database.remove(receivedCookie);
			System.out.println("Error: pwd is not right");
//			System.out.println("receivedPwdStr: "+receivedPwdStr);
//			System.out.println("pwd: "+pwd);
			return 3;
		}
		byte[] iv = new byte[16];
		System.arraycopy(receivedPwd, 16, iv, 0, 16);
//		System.out.println("iv iv iv !!"+new String(iv));
		byte[] gAModP = ed.decryptPrivate(secondMessageDetail.gABModP, "server");
		DiffieHellman dh = new DiffieHellman();
		byte[] gBModP = dh.genPublicKey();
		byte[] aesKey = dh.genAESKey(gAModP).getEncoded();
		int c1 = ServiceMethods.genRandom();
			
		Message dhMessage = new Message();
		dhMessage.TYPE = "THIRD MESSAGE";
		MessageDetail thirdMessageDetail = new MessageDetail();
		thirdMessageDetail.gABModP = ed.encryptPublic(gBModP, "client");
		byte[] c1Byte = ByteBuffer.allocate(4).putInt(c1).array();
		thirdMessageDetail.c1 = ed.encryptPublic(c1Byte, "client");
		dhMessage.data = so.serialize(thirdMessageDetail);
				
		OutputStream outStream;
		try {
			outStream = socket.getOutputStream();
			outStream.write(so.serialize(dhMessage));
					
			// wait for K{c1},c2 from user
			InputStream inStream = socket.getInputStream();
			Message fourthMessage = (Message) so.deserialize(ServiceMethods.readFully(inStream));
			if (!fourthMessage.cookie.equals(receivedCookie)) {
				System.out.println("Error: cookie is not right");
				return 4;
			}
			
			MessageDetail fourthMessageDetail = (MessageDetail) so.deserialize(fourthMessage.data);
			byte[] KC1 = fourthMessageDetail.KC;
			byte[] decryptedC1 = ed.decrypt(aesKey, KC1, iv);
			int receivedC1 = new BigInteger(decryptedC1).intValue();
			if (c1 != receivedC1) {
//				ChatServer.database.remove(receivedCookie);
				System.out.println("Error: c1 is not right in login message");
				return 5;
			}
			int c2 = fourthMessageDetail.c2;
//			System.out.println("c1 is right as decrypted!!");
								
			// records chat port of that client at the same time
			byte[] KC2 = ed.encrypt(aesKey, c2, iv);
			MessageDetail lastMessageDetail = new MessageDetail();
			lastMessageDetail.c1 = KC2;
								
			int clientChatPort = socket.getPort();
			lastMessageDetail.c2 = clientChatPort;
			Message lastMessage = new Message();
			lastMessage.TYPE = "LAST MESSAGE";
			lastMessage.data = so.serialize(lastMessageDetail);
			outStream.write(so.serialize(lastMessage));
								
			// update data in database;
			serverData = ChatServer.database.get(receivedCookie);
			serverData.username = username;
			serverData.port = clientChatPort;
			serverData.aesKey = aesKey;
			serverData.status = "ONLINE";
			serverData.iv = iv;
			ChatServer.database.put(receivedCookie, serverData);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return 0;
	}

	/**
	 * Establish a secret key for client initiator and the acceptor
	 * @param initiator client who wants to start the communication
	 * @param acceptor client who is invited for communication
	 * @return return the secret key for client initiator and acceptor
	 */
	public int keyEstablish(Socket socket, Message ticketMessage) {
		String receivedCookie = ticketMessage.cookie;
		if (!ChatServer.database.containsKey(receivedCookie)) {
			System.out.println("Error: request from offline or unregistered users");
			return 1;
		}
		ServerData serverData = ChatServer.database.get(receivedCookie);
		
		EncryptDecrypt ed = new EncryptDecrypt();
		byte[] aesKey = serverData.aesKey;
		byte[] deTicketMsgDetail = ed.decrypt(aesKey, ticketMessage.data, serverData.iv);
		SerializeObject so = new SerializeObject();
		MessageDetail ticketMessageDetail = (MessageDetail) so.deserialize(deTicketMsgDetail);
		
		// cookie doesn't correspond with username
		if (!ticketMessageDetail.userA.equals(serverData.username)) {
			System.out.println("Error: cookie doesn't correspond with username");
			return 2;
		}
		String peer = ticketMessageDetail.userB;
		if (getUserInfoData(peer) == null) {
			System.out.println("Error: requested user is not online");
			return 3;
		}
		int n1 = ticketMessageDetail.c2;
		
		// send ticket to user
		MessageDetail ticketDetial = new MessageDetail();
		ticketDetial.userB = peer;
		ServerData peerData = getUserInfoData(peer);
		ticketDetial.ip = peerData.ip;
		ticketDetial.port = peerData.port;
		ticketDetial.c2 = n1;
		byte[] KAB = ServiceMethods.generateSecretKey();
		ticketDetial.KAB = KAB;
		ticketDetial.c1 = peerData.iv;
		
		MessageDetail ticket = new MessageDetail();
		ticket.userA = ticketMessageDetail.userA;
		ticket.KAB = KAB;
		ticket.c1 = serverData.iv;
		ticket.expire = System.currentTimeMillis() + (1000*60*12);
		byte[] ticketByte = ed.encrypt(peerData.aesKey, so.serialize(ticket), peerData.iv);
		ticketDetial.ticket = ticketByte;
		
		Message sendTicket = new Message();
		sendTicket.TYPE = "SEND TICKET";
		sendTicket.data = ed.encrypt(aesKey, so.serialize(ticketDetial), serverData.iv);
		OutputStream outputStream;
		try {
			outputStream = socket.getOutputStream();
			outputStream.write(so.serialize(sendTicket));
//			System.out.println("key establishment with server is done!");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return 0;
	}
	
	public ServerData getUserInfoData (String username) {
		HashMap<String, ServerData> copy = ChatServer.database;
		for (ServerData serverData : copy.values()) {
		    if (serverData.getUsername() != null && serverData.username.equals(username)) return serverData;
		}
		return null;
	}
	
	/**
	 * This function is called when a client log out
	 * @param client
	 */
	public void logout(Socket socket, Message message) {
		String cookie =  message.cookie;
		if (!ChatServer.database.containsKey(cookie)) {
			System.out.println("Error: wrong cookie!");
			return;
		}
		ServerData serverData = ChatServer.database.get(cookie);
		String username = serverData.username;
		byte[] aesKey = serverData.aesKey;
		byte[] iv = serverData.iv;
		
		EncryptDecrypt ed = new EncryptDecrypt();
		SerializeObject so = new SerializeObject();
		MessageDetail msgDetail = (MessageDetail) so.deserialize(ed.decrypt(aesKey, message.data, iv));
		int n1 = msgDetail.c2;
		int n2 = ServiceMethods.genRandom();
		
		MessageDetail replyFinDetail = new MessageDetail();
		replyFinDetail.c2 = n1-1;
		replyFinDetail.c3 = n2;
		Message replyFin = new Message();
		replyFin.TYPE = "FIN-ACK";
		replyFin.data = ed.encrypt(aesKey, so.serialize(replyFinDetail), iv);
		
		try {
			OutputStream outputStream = socket.getOutputStream();
			outputStream.write(so.serialize(replyFin));
			
			InputStream inputStream = socket.getInputStream();
			Message finMessage = (Message) so.deserialize(ServiceMethods.readFully(inputStream));
			if (!finMessage.TYPE.equals("ACK")) {
				System.out.println("message type is not ACK");
				return;
			}
			if (!finMessage.cookie.equals(cookie)) {
				System.out.println("cookie is not right");
				return;
			}
			byte[] decryptC1 = ed.decrypt(aesKey, finMessage.data, iv);
			if (new BigInteger(decryptC1).intValue() != n2-1) {
				System.out.println("n2 in logout message is not right");
				return;
			}
			ChatServer.database.remove(cookie);
			System.out.println("user log out successfully!");
			// broadcast logout to other users
			broadcastLogout(username);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	/**
	 * Broadcast to all online clients that certain client is off line
	 * @param username
	 */
	public static void broadcastLogout(String username) {
		HashMap<String, ServerData> copy = new HashMap<String, ServerData>(ChatServer.database);
		for (ServerData serverData : copy.values()) {
		    InetAddress ip = serverData.ip;
		    int port = serverData.port;
		    Message broadcast = new Message();
		    broadcast.TYPE = "BROADCAST LOGOUT";
		    broadcast.cookie = username;
		    SerializeObject so = new SerializeObject();
		    byte[] sendData = so.serialize(broadcast);
		    
		    DatagramSocket socket;
			try {
				socket = new DatagramSocket();
				DatagramPacket sendPacket = new DatagramPacket(sendData, sendData.length, ip, port);
			    socket.send(sendPacket);
			} catch (SocketException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}

	/**
	 * This function is called when certain client call the list command for all online clients
	 * 
	 */
	public void sendOnlineList(Socket socket, Message message) {
		String cookie = message.cookie;
		
		if (!ChatServer.database.containsKey(cookie)) {
			System.out.println("list command from unknown user");
			return;
		}
		// check status?!
		StringBuilder sb = new StringBuilder();
		HashMap<String, ServerData> map = ChatServer.database;
		for (ServerData serverData : map.values()) {
			sb.append(", ");
		    sb.append(serverData.username);
		}
		Message msgReply = new Message();
		msgReply.TYPE = "LIST REPLY";
		
		byte[] aesKey = map.get(cookie).aesKey;
		byte[] iv = map.get(cookie).iv;
		EncryptDecrypt ed = new EncryptDecrypt();
		msgReply.data = ed.encrypt(aesKey, sb.toString().substring(2).getBytes(), iv);
		
		SerializeObject so = new SerializeObject();
		try {
			OutputStream outputStream = socket.getOutputStream();
			outputStream.write(so.serialize(msgReply));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
