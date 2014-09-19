package chatClient;

import java.io.IOException;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;

import Service.DiffieHellman;
import Service.EncryptDecrypt;
import Service.Message;
import Service.MessageDetail;
import Service.SerializeObject;
import Service.ServiceMethods;

public class IncommingChatThread extends Thread {
	public static DatagramSocket chatSocket;
	
	public Clients clients;
	
	public IncommingChatThread( Clients client) {
		try {
			chatSocket = new DatagramSocket(ChatClient.chatPort);
			clients = client;
			this.start();
		} catch (SocketException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public void run() {
		while (true) {
			byte[] receiveData = new byte[65536];
			DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);
			
			try {
				chatSocket.receive(receivePacket);
				SerializeObject so = new SerializeObject();
				Message message = (Message) so.deserialize(receiveData);
				String type = message.TYPE;
				if (type.equals("REQUEST TALK")) {
					InetAddress ip = receivePacket.getAddress();
					int port = receivePacket.getPort();
					
					clients.acceptTalk(message, ip, port);
				} else if (type.equals("REPLY TALK REQUEST")){
					InetAddress ip = receivePacket.getAddress();
					int port = receivePacket.getPort();
					clients.responseTalkRequest(message, ip, port);
					
				} else if (type.equals("LAST TALK REQUEST")) {
					System.out.println("time too long, no longer waiting!");
					
				} else if (type.equals("KEY GOT")) {
					clients.acceptKeyBuild(message, receivePacket.getAddress(), receivePacket.getPort());
					
				} else if (type.equals("TALK")) {
					clients.printMessage(message, receivePacket.getAddress(), receivePacket.getPort());
					
				} else if (type.equals("BROADCAST LOGOUT")) {
					String peername = message.cookie;
					if (ChatClient.peers.containsKey(peername)) {
						System.out.println(peername+" has loged out");
						ChatClient.peers.remove(peername);
					}
					
				}else {
					System.out.println("wrong type of peer to peer talk message type");
				}
			
			} catch (IOException e) {
				// TODO Auto-generated catch block
				chatSocket.close();
				e.printStackTrace();
			}
		}
	}
}
