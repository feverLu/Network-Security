package chatServer;

import java.util.HashMap;
import java.util.Map;

public class CheckAliveThread extends Thread {
	public CheckAliveThread() {
		this.start();
	}

	public void run() {
		while(true) {
			try {
				Thread.sleep(3000);
				HashMap<String, ServerData> copy = new HashMap<String, ServerData>(ChatServer.database);
				for (Map.Entry<String, ServerData> entry : copy.entrySet()) {
				    String cookie = entry.getKey();
				    ServerData serverData = entry.getValue();
				    if (serverData.getTimeStamp() < System.currentTimeMillis()) {
				    	System.out.println("yes, I deleted the user with illeagal logout");
						ChatServer.database.remove(cookie);
						Server.broadcastLogout(serverData.getUsername());
				    }
				}
			} catch (InterruptedException e) {					
				// TODO Auto-generated catch block
				System.out.println("this thread is interrupted");
				e.printStackTrace();
			}
		}
	}
}
