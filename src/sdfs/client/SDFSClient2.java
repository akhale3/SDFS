package sdfs.client;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.UnknownHostException;
import java.nio.file.FileSystems;
import java.nio.file.Path;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class SDFSClient2 {
	
	private DataInputStream inFromServer = null;
	private DataOutputStream outToServer = null;
	private static FileInputStream fileIS = null;
	
	private SSLSocketFactory sslFact = null;
	private SSLSocket clientSocket = null;
	
	void startFSSession() throws UnknownHostException, IOException
	{
		sslFact = (SSLSocketFactory)SSLSocketFactory.getDefault();
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
	
	void sendCert() throws IOException
	{
		putFile("hello_cert");
	}
	
	void putFile(String fileUID) throws IOException
	{
		int length;
		Long fileLength;
		Path filePath = FileSystems.getDefault().getPath(".", "/", fileUID);
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
		SDFSClient2 client = new SDFSClient2();
		client.startFSSession();
		if (client.clientSocket == null)
		{
			client.sendCert();
		}
		client.putFile("test");
		client.endSession();
	 }

}
