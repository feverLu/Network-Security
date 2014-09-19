package nc_ps1;

import java.net.*;
import java.util.Set;

public class GreetClients {
	// client must has IP address and port information
	int port;
	InetAddress IPAdress;
	
	// default constructor to create a new client
	public GreetClients (InetAddress clientIPAddress, int clientPort) {
		port = clientPort;
		IPAdress = clientIPAddress;
	}
	
	public boolean ifAlreadyClient(int clientPort, InetAddress clientIPAddress, Set<GreetClients> greetClients) {
		GreetClients client = new GreetClients(clientIPAddress, clientPort);
		return (greetClients.contains(client));
	}
	
	// add this client to the server's client list
	public void addClient(int clientPort, InetAddress clientIPAddress, Set<GreetClients> greetClients) {
		GreetClients client = new GreetClients(clientIPAddress, clientPort);
		if (!greetClients.contains(client)) {
			greetClients.add(client);
		}
	}
	
	public void delClient(int clientPort, InetAddress clientIPAddress, Set<GreetClients> greetClients) {
		GreetClients client = new GreetClients(clientIPAddress, clientPort);
		if (greetClients.contains(client)) {
			greetClients.remove(client);
		}
	}
	
	public int getPort () {
		return port;
	}
	
	public InetAddress getIPAddress () {
		return IPAdress;
	}
}
