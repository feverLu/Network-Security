package nc_ps1;

import java.io.*;
import java.net.*;

public class UDPClient {
	private static DatagramSocket clientSocket;

	public static void main(String[] args) throws Exception {
		clientSocket = new DatagramSocket();
	    byte[] sendData = new byte[1024];
	    byte[] receiveData = new byte[1024];
	    
	    //input arguments, the first one is the server hot name and the second is the server's port number
		InetAddress serverIPAddress = InetAddress.getByName(args[0]);
		int serverPort = Integer.parseInt(args[1]);
	    
		// begin greeting
		String greeting = "GREETING";
	    sendData = greeting.getBytes();
	    DatagramPacket sendGreet = new DatagramPacket(sendData, sendData.length, serverIPAddress, serverPort);
	    clientSocket.send(sendGreet);
	      
	    System.out.println("Port Number: " + clientSocket.getPort());
	    System.out.println("Host Name: " + clientSocket.getLocalAddress().getHostName());
	     
	    DatagramPacket receiveGreet = new DatagramPacket(receiveData, receiveData.length);
	    clientSocket.receive(receiveGreet);
	    String greeted = new String(receiveGreet.getData());
	    System.out.println(greeted);
	      
	    if (greeted.contains("GREETED") && receiveGreet.getAddress().equals(serverIPAddress) && receiveGreet.getPort() == serverPort) {
	    	System.out.println("Greeted");
	    	  
	    	MyRunnable myRunnable = new UDPClient().new MyRunnable(); 
		    Thread myThread = new Thread(myRunnable);
		    myThread.start(); 
	    	
		    // main thread to read I/O continuously
	    	while(true){
	    		BufferedReader userInput =
					         new BufferedReader(new InputStreamReader(System.in));
			    String message = "MESSAGE:" + userInput.readLine();
			    System.out.println("Input:" + message);
			    sendData = message.getBytes();
			    DatagramPacket sendPacket = new DatagramPacket(sendData, sendData.length, serverIPAddress, serverPort);
			    clientSocket.send(sendPacket);
	    	  }
	      }
	   }
	
	// second thread receive packets continuously
	class MyRunnable implements Runnable { 
		   public void run() { 
		       while ( true ) { 
		   	       byte[] receiveData = new byte[1024];
		    	   DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);
				      try {
				    	  clientSocket.receive(receivePacket);
				    	  String receivedMessage = new String(receivePacket.getData());
				    	  System.out.println("From Sever:" + receivedMessage);
					      //clientSocket.close(); 
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}   
		       } 
		   } 
		} 
}
