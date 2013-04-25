package sdfs.client;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.UnknownHostException;
import java.nio.charset.Charset;
import java.nio.file.FileSystems;
import java.nio.file.Path;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class SDFSClient2 {
	
	private InputStream inFromServer = null;
	private OutputStream outToServer = null;
	private static FileInputStream fileIS = null;
	
	private SSLSocketFactory sslFact = null;
	private SSLSocket clientSocket = null;
	
	private final String[] enabledCipherSuites = { "SSL_DH_anon_WITH_RC4_128_MD5" };
	
	void startFSSession() throws UnknownHostException, IOException
	{
		sslFact = (SSLSocketFactory)SSLSocketFactory.getDefault();
		clientSocket = (SSLSocket)sslFact.createSocket("localhost", 6789);
		
		clientSocket.setEnabledCipherSuites(enabledCipherSuites);
		
		inFromServer = clientSocket.getInputStream();
		outToServer = clientSocket.getOutputStream();
	}
	
	void getFile() throws UnknownHostException, IOException
	{
		
	}
	
	void putFile(String fileUID) throws IOException
	{
		int length;
		String fileName;
		Long fileLength;
		Path filePath = FileSystems.getDefault().getPath(".", "/", fileUID);
		File file = new File(filePath.toString());
		byte[] buffer = new byte[1024];
		fileIS = new FileInputStream(file);
		fileName = file.getName();
		outToServer.write(fileName.getBytes(Charset.forName("UTF-8")));
		outToServer.write('\n');
		outToServer.flush();
		fileLength = new Long(file.length());;
		outToServer.write(fileLength.toString().getBytes());
		outToServer.write('\n');
		outToServer.flush();
		while ((length = fileIS.read(buffer)) != -1)
		{
			outToServer.write(buffer, 0, length);
		}
	}
	
	void sendCert() throws IOException
	{
		putFile("./test.cert");
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
		client.sendCert();
//		client.putFile("hello_cert");
		client.endSession();
	 }

}
