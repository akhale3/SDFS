package sdfs.server;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.Principal;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import javax.security.auth.x500.X500Principal;

public class SDFSServer {
	
	private DataInputStream inFromClient = null;
	@SuppressWarnings("unused")
	private DataOutputStream outToClient = null;
	private static FileInputStream fileIS = null;
	private FileOutputStream fileOS = null;
	
	private SSLServerSocketFactory sslSockFact = null;
	private SSLServerSocket server = null;
	private SSLSocket serverSocket = null;
	private static SSLContext sslContext = null;
	
	static boolean verifyEntity(SSLSession session) throws SSLPeerUnverifiedException
	{
		boolean value = true;//false;
		Principal clientID = session.getPeerPrincipal();
		if (clientID instanceof X500Principal)
		{
			@SuppressWarnings("unused")
			X500Principal x500 = (X500Principal)clientID;
//			value = x500.getName().equals("CN=Certificate");
			return value;
		}
		return value;
	}
	
	static SSLContext setupContext() throws Exception
	{
		KeyManagerFactory kMFact = KeyManagerFactory.getInstance("SunX509");
		KeyStore serverStore = KeyStore.getInstance("JKS");
		fileIS = new FileInputStream("server.jks");
		serverStore.load(fileIS, "serverPwd".toCharArray());
		kMFact.init(serverStore, "serverPwd".toCharArray());
		
		TrustManagerFactory tMFact = TrustManagerFactory.getInstance("SunX509");
		KeyStore trustStore = KeyStore.getInstance("JKS");
		fileIS = new FileInputStream("trustStore.jks");
		trustStore.load(fileIS, "trustPwd".toCharArray());
		tMFact.init(trustStore);
		
		SSLContext sslContext = SSLContext.getInstance("TLS");
		sslContext.init(kMFact.getKeyManagers(), tMFact.getTrustManagers(), null);
		
		return sslContext;
	}
	
	boolean startFSSession() throws IOException
	{
		sslSockFact = sslContext.getServerSocketFactory();
		server = (SSLServerSocket)sslSockFact.createServerSocket(6789);
		server.setNeedClientAuth(true);
		System.out.println("Status: Awaiting connection ...");
		serverSocket = (SSLSocket)server.accept();
		serverSocket.startHandshake();
		if (verifyEntity(serverSocket.getSession()))
		{
			System.out.println("Status: Connected");
			inFromClient = new DataInputStream(serverSocket.getInputStream());
			outToClient = new DataOutputStream(serverSocket.getOutputStream());
			return true;
		}
		return false;
	}
	
	void getFile() throws IOException
	{
		int length;
		Long fileLength;
		byte[] buffer;
		Path filePath = FileSystems.getDefault().getPath("./recv/", "test");
		fileLength = new Long(inFromClient.readLong());
		fileOS = new FileOutputStream(filePath.toString());
		buffer = new byte[fileLength.intValue()];
		while ((length = inFromClient.read(buffer)) > 0)
		{
			fileOS.write(buffer, 0, length);
		}
	}
	
	void endFSSession() throws IOException
	{
		serverSocket.close();
	}
	
	public static void main(String args[]) throws Exception
      {
		boolean valid = false;
		SDFSServer serv = new SDFSServer();
		sslContext = setupContext();
		valid = serv.startFSSession();
		if (valid)
		{
			serv.getFile();
			serv.endFSSession();
		}
      }
}