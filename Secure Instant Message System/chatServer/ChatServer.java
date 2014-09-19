package chatServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashMap;
import java.util.Properties;

import Service.Message;
import Service.SerializeObject;
import Service.ServiceMethods;

public class ChatServer {
	public static HashMap<String, ServerData> database = new HashMap<String, ServerData>();
	
	public static void main (String args[]) {
		Properties prop = ServiceMethods.loadProperties();
		int serverPort = Integer.valueOf(prop.getProperty("serverPort"));

		CheckAliveThread checkAliveThread = new CheckAliveThread();
		try {
			ServerSocket serverSocket =  new ServerSocket(serverPort);
			while (true) {
				ThreadSocket threadSocket = new ThreadSocket(serverSocket.accept());
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}

class ThreadSocket extends Thread {
	private Socket socket;
	
	ThreadSocket(Socket insocket) {
		socket = insocket;
		this.start();
	}
	
	public void run() {
		try {			
			Server server = new Server();
			InputStream inputStream = socket.getInputStream();	
			OutputStream outputStream = socket.getOutputStream();

			SerializeObject so = new SerializeObject();
			Message message = (Message) so.deserialize(ServiceMethods.readFully(inputStream));
			String type = message.getType();
			
			if (type == null) {
				System.out.println("message type is missing");
			} else if (type.equals("REQUEST LOGIN")) {
				server.replyCookie(socket);
			} else if (type.equals("AUTHENTICATE")){
				// second part of login request
				int error = server.authenticate(socket, message);
				if (error > 0) {
					Message errorMessage = new Message();
					errorMessage.TYPE = "ERROR";
					if (error == 1) {
						errorMessage.data = "Error: cookie does not exit in our database".getBytes();
					} else if (error == 2) {
						errorMessage.data = "Error: ip address does not  correspond to the cookie".getBytes();
					} else if (error == 3) {
						errorMessage.data = "Error: pwd is not right".getBytes();
					} else if (error == 4) {
						errorMessage.data = "Error: cookie is not right".getBytes();
					} else if (error == 5) {
						errorMessage.data = "Error: c1 is not right in login message".getBytes();
					} else if (error == 6) {
						errorMessage.data = "Error: user already online".getBytes();
					}
					outputStream.write(so.serialize(errorMessage));
				}
			} else if (type.equals("KEY ESTABLISHMENT")) {
				int error = server.keyEstablish(socket, message);
				if (error > 0) {
					Message errorMessage = new Message();
					errorMessage.TYPE = "ERROR";
					if (error == 1) {
						errorMessage.data = "Error: request from offline or unregistered users".getBytes();
					} else if (error == 2) {
						errorMessage.data = "Error: cookie doesn't correspond with username".getBytes();
					} else if (error == 3) {
						errorMessage.data = "Error: requested user is not online".getBytes();
					} 
					outputStream.write(so.serialize(errorMessage));
				}
			} else if (type.equals("LIST PEERS")) {
				server.sendOnlineList(socket, message);
			} else if (type.equals("FIN")) {
				server.logout(socket, message);
			} else if (type.equals("ALIVE")) {
				String cookie = message.cookie;
//				ServerData serverData = ChatServer.database.get(cookie);
//				serverData.setTimeStamp(System.currentTimeMillis() + (1000*3));
//				ChatServer.database.put(cookie, serverData);
				ChatServer.database.get(cookie).setTimeStamp(System.currentTimeMillis()+3000);
			}
			socket.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
