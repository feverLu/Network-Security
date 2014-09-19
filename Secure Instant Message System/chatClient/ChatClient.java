package chatClient;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.Properties;

import Service.ServiceMethods;

public class ChatClient {
	public static String cookie;
	
	public static byte[] aesKey;
	
	public static int chatPort;
	
	public static String userA;
	
	public static byte[] iv;
	
	public static HashMap<String, PeerInfo> peers = new HashMap<String, PeerInfo>();

	public static void main (String args[]) throws InterruptedException {
		try {
			BufferedReader bReader = new BufferedReader(new InputStreamReader(System.in));
		    System.out.print("Enter username:	");
			String username = bReader.readLine();
			System.out.print("Enter password:	");
			String pwd = bReader.readLine();
			
			Clients client = new Clients();
			Properties prop = ServiceMethods.loadProperties();
			InetAddress ip = InetAddress.getByName(prop.getProperty("serverIpAdd"));
			int port = Integer.valueOf(prop.getProperty("serverPort"));
			int logTry = client.login(username, pwd, ip, port);
			if (logTry != 0) {
				System.out.println("Error: login failed, please retry");
				System.exit(1);
			} else {
				System.out.println("login successfully!");
			}
			
			// start listening to the chat port
			IncommingChatThread chatThread = new IncommingChatThread(client);
			KeepAliveThread keepAliveThread = new KeepAliveThread();
			
			System.out.println();
			System.out.println("Commands:");
			System.out.println("	-list					request all the online user names from server");
			System.out.println("	-send [username] [message]		send message to user with the given username");
			System.out.println("	-logout					request to log out");
			System.out.println();
			
			while (true) {
				String command = bReader.readLine();
				if (command.startsWith("-send")) {
					String[] commands = command.split(" ");
					if (commands.length < 3) {
						System.out.println("Usage: -send [username] [message]");
						continue;
					}
					String peerTalkName = commands[1];
					String message = command.substring(commands[0].length()+commands[1].length()+2);
					if (peers.containsKey(commands[1])) {
						client.communicate(peerTalkName, message);
					} else {
						if (commands[1].equals(userA)) {
							System.out.println("Error: can not send message to yourself");
							continue;
						}
						int error = client.keyEstablish(peerTalkName, ip, port);
						Thread.sleep(500);
						if (error > 0) continue;
						client.communicate(peerTalkName, message);
					}
				} else if (command.startsWith("-list")) {
					client.getOnlineList(ip, port);
				} else if (command.startsWith("-logout")) {
					client.logout(ip, port);
					System.exit(1);
				} else {
					System.out.println("wrong command");
				}
			}
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
