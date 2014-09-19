package nc_ps1;

import java.net.*;
import java.util.HashSet;
import java.util.Set;

public class UDPServer {
	private static DatagramSocket serverSocket;
	
	public UDPServer (String serverHost, int serverPort){
		try {
//			System.out.println("Server Host: "+serverHost);
//			System.out.println("Server Port: "+Integer.toString(serverPort));
			serverSocket = new DatagramSocket(serverPort, InetAddress.getByName(serverHost));
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			System.out.println("ip address can't be found with the given host name");
			e.printStackTrace();
		} catch (SocketException e) {
			// TODO Auto-generated catch block
			System.out.println("fails to create the server socket");
			e.printStackTrace();
		}

	
	public static void main(String[] args) throws Exception {
	    Set<GreetClients> clients = new HashSet<GreetClients>();
	    System.out.println("Server Initialized...");
	    
	    // input arguments, the first one is the server host name and the second is the server's port number
	    String serverHost = args[0];
	    int serverPort = Integer.parseInt(args[1]);
	    UDPServer udpserver = new UDPServer (serverHost, serverPort);
//		System.out.println("b"+Integer.toString(port));
	    
	    // procedure receive packets continuously and broadcast each the server receives a message 
	    while(true)
	    {
	    	byte[] receiveData = new byte[1024];
		    byte[] sendData = new byte[1024];
		    DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);
	        serverSocket.receive(receivePacket);
	        String message = new String( receivePacket.getData());
	        InetAddress clientIPAddress = receivePacket.getAddress();
	        int clientPort = receivePacket.getPort();
	        
	        System.out.println("Received: " + message);
	        System.out.println("Client: "+String.valueOf(clientPort));
	        
	        if (message.contains("MESSAGE:")) {
	        	// when the server receive a message, add sender's IP address and port information and broadcast it to every clinet
	        	String incomingMessage = "<From " + clientIPAddress.getHostAddress() + ":" + Integer.toString(clientPort) + ">:" + message.substring(8);   
	        	System.out.println(incomingMessage);
		        sendData = incomingMessage.getBytes();
		        
		        for (GreetClients client : clients) {
		        	System.out.println("send port: "+client.getPort());
		        	DatagramPacket sendPacket =
			        		new DatagramPacket(sendData, sendData.length, client.getIPAddress(), client.getPort());
			        serverSocket.send(sendPacket);
		        }
	        } else if (message.contains("GREETING")) {
	        	// when the server receive a greeting, it add this client to its client list
	        	GreetClients greetingClient = new GreetClients(clientIPAddress, clientPort);
	        	clients.add(greetingClient);
	        	
	        	String greeted = "GREETED";
	        	sendData = greeted.getBytes();
	        	DatagramPacket sendGreet = 
	        			new DatagramPacket(sendData, sendData.length, clientIPAddress, clientPort);
	        	serverSocket.send(sendGreet);
	        } 
	    }
	}
}
