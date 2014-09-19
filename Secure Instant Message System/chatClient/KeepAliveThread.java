package chatClient;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.Properties;

import Service.Message;
import Service.SerializeObject;
import Service.ServiceMethods;

public class KeepAliveThread extends Thread{
	InetAddress ip;
	int port;
	SerializeObject so;
	public KeepAliveThread() {
		Properties prop = ServiceMethods.loadProperties();
		try {
			ip = InetAddress.getByName(prop.getProperty("serverIpAdd"));
			port = Integer.valueOf(prop.getProperty("serverPort"));
			
			so = new SerializeObject();
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
		this.start();
	}

	public void run() {
		while(true) {
			try {
				Thread.sleep(2000);
				
				Socket socket = new Socket(ip, port);
				Message aliveMessage = new Message();
				aliveMessage.TYPE = "ALIVE";
				aliveMessage.cookie = ChatClient.cookie;
				OutputStream outputStream = socket.getOutputStream();
				outputStream.write(so.serialize(aliveMessage));
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				System.out.println("sleep thread is interrupted");
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				System.out.println("socekt outpurstream IOException");
				System.out.println();
				e.printStackTrace();
			} 
		}
	}
}
