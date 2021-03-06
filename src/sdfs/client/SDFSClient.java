package sdfs.client;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.UnknownHostException;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

public class SDFSClient {
	
	private DataInputStream inFromServer = null;
	private DataOutputStream outToServer = null;
	private static FileInputStream fileIS = null;
	
	private static SSLContext sslContext = null;
	private SSLSocketFactory sslFact = null;
	private SSLSocket clientSocket = null;
	
	static SSLContext setupContext() throws NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException, KeyManagementException, UnrecoverableKeyException
	{
		KeyManagerFactory kMFact = KeyManagerFactory.getInstance("SunX509");
		KeyStore clientStore = KeyStore.getInstance("PKCS12");
		fileIS = new FileInputStream("client.p12");
		clientStore.load(fileIS, "clientPwd".toCharArray());
		kMFact.init(clientStore, "clientPwd".toCharArray());
		
		TrustManagerFactory tMFact = TrustManagerFactory.getInstance("SunX509");
		KeyStore trustStore = KeyStore.getInstance("JKS");
		fileIS = new FileInputStream("trustStore.jks");
		trustStore.load(fileIS, "trustPwd".toCharArray());
		tMFact.init(trustStore);
		
		SSLContext sslContext = SSLContext.getInstance("TLS");
		sslContext.init(kMFact.getKeyManagers(), tMFact.getTrustManagers(), null);
		
		return sslContext;
	}
	
	void startFSSession() throws UnknownHostException, IOException
	{
		sslFact = sslContext.getSocketFactory();
		clientSocket = (SSLSocket)sslFact.createSocket("localhost", 6789);
		inFromServer = new DataInputStream(clientSocket.getInputStream());
		outToServer = new DataOutputStream(clientSocket.getOutputStream());
	}
	
	void getFile() throws UnknownHostException, IOException
	{
/*
		String sentence;
		String modifiedSentence;
		
		BufferedReader inFromUser = new BufferedReader( new InputStreamReader(System.in));
		BufferedReader inFromServer = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
		
		sentence = inFromUser.readLine();
		outToServer.writeBytes(sentence + '\n');
		modifiedSentence = inFromServer.readLine();
		System.out.println("FROM SERVER: " + modifiedSentence);
*/
	}
	
	void putFile(String fileUID) throws IOException
	{
		int length;
		Long fileLength;
		Path filePath = FileSystems.getDefault().getPath("./", fileUID);
		File file = new File(filePath.toString());
		byte[] buffer = new byte[1024];
		fileIS = new FileInputStream(file);
		fileLength = new Long(file.length());
		outToServer.writeLong(fileLength.longValue());
		outToServer.flush();
		while ((length = fileIS.read(buffer)) != -1)
		{
			outToServer.write(buffer, 0, length);
		}
		outToServer.flush();
	}
	
	void delegate()
	{
		
	}
	
	void endSession() throws IOException
	{
		fileIS.close();
		outToServer.close();
		inFromServer.close();
		clientSocket.close();
	}
	
	public static void main(String argv[]) throws Exception
	 {
		SDFSClient client = new SDFSClient();
		sslContext = setupContext();
		client.startFSSession();
		client.putFile("test");
		client.endSession();
	 }

}
