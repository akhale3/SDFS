package sdfs.client;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.Charset;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.bouncycastle.openssl.PEMWriter;

import sdfs.ca.CertAuth;

/**
 * 
 * @author anish
 *
 */

public class SDFSClient2 {
	
	private InputStream inFromServer = null;
	private OutputStream outToServer = null;
	private FileInputStream fileIS = null;
	private FileOutputStream fileOS = null;
	
	private SSLSocketFactory sslFact = null;
	private SSLSocket clientSocket = null;
	
	private final String[] enabledCipherSuites = { "SSL_DH_anon_WITH_RC4_128_MD5" };
	
	Path computeFilePath(String fileUID)
	{
		Path filePath;
		filePath = FileSystems.getDefault().getPath("./", "src", "sdfs", "client", fileUID);
		return filePath;
	}
	
	@SuppressWarnings("unused")
	void getFile(String fileUID) throws UnknownHostException, IOException
	{
		int length;
		String fileName;
		String suffix;
		int fileLength;
		String temp;
		File file = null;
		Path filePath = null;
		BufferedReader input = new BufferedReader(new InputStreamReader(inFromServer));
		
		outToServer.write("put".getBytes());
		outToServer.write('\n');
		
		fileName = fileUID;
		
		outToServer.write(fileName.getBytes(Charset.forName("UTF-8")));
		outToServer.write('\n');
		outToServer.flush();
		
		suffix = fileName.substring(fileName.lastIndexOf('.') + 1, fileName.length()).trim();
		if(suffix.equalsIgnoreCase("cert"))
		{
			filePath = computeFilePath("certs/" + fileName);
		}
		else
		{
			filePath = computeFilePath(fileName);
		}
		
		fileOS = new FileOutputStream(filePath.toString());

		temp = input.readLine();
		length = temp.length();
		fileOS.write(temp.getBytes(), 0, length);
		
		while(true)
		{
			temp = input.readLine();
			if(temp.equalsIgnoreCase("eof"))
			{
				break;
			}
			length = temp.length();
			fileOS.write("\n".getBytes(), 0, 1);
			fileOS.write(temp.getBytes(), 0, length);
		}
		
		outToServer.write('\n');
	}
	
	boolean putFile(String fileUID) throws IOException
	{
		int length;
		String fileName;
		Path filePath = computeFilePath(fileUID);
		File file = new File(filePath.toString());
		
		outToServer.write("get".getBytes());
		outToServer.write('\n');
		
		if(file.exists())
		{
			byte[] buffer = new byte[1024];
			fileIS = new FileInputStream(file);
			fileName = file.getName();
			
			outToServer.write(fileName.getBytes(Charset.forName("UTF-8")));
			outToServer.write('\n');
			outToServer.flush();
			
			while ((length = fileIS.read(buffer)) > 0)
			{
				outToServer.write(buffer, 0, length);
			}
			
			outToServer.write('\n');
			outToServer.write("eof".getBytes());
			outToServer.write('\n');
			return true;
		}
		else
		{
			System.out.println(fileUID + " does not exist");
			System.out.println("Acquiring client certificate ...");
			return false;
		}
	}
	
	void delegate(String clientID)
	{
		
	}
	
	void sendCert() throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, CertificateEncodingException, SecurityException, SignatureException
	{
		String subject = InetAddress.getLocalHost().getHostName();
		String suffix = ".cert";
		boolean certExists = false;
		
		certExists = putFile("certs/" + subject + suffix);
		if(!certExists)
		{
			// Invoke sdfs.CertAuth.generateCert()
			KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
	        kpGen.initialize(1024, new SecureRandom());
	    	KeyPair pair = kpGen.generateKeyPair();
	    	X509Certificate clientCert = CertAuth.generateCert(subject, pair);
	    	PEMWriter pemWrt = new PEMWriter(new BufferedWriter(new FileWriter("./src/sdfs/client/certs/" + subject + suffix)));
			pemWrt.writeObject(clientCert);
			pemWrt.close();
			certExists = putFile("certs/" + subject + suffix);
		}
	}
	
	void startFSSession(String server_host, int port_no) throws UnknownHostException, IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, CertificateEncodingException, SecurityException, SignatureException
	{
		sslFact = (SSLSocketFactory)SSLSocketFactory.getDefault();
		clientSocket = (SSLSocket)sslFact.createSocket(server_host, port_no);
		
		clientSocket.setEnabledCipherSuites(enabledCipherSuites);
		
		inFromServer = clientSocket.getInputStream();
		outToServer = clientSocket.getOutputStream();
		
		sendCert();
	}
	
	void endSession() throws IOException
	{
		fileIS.close();
		fileOS.close();
		outToServer.close();
		inFromServer.close();
		clientSocket.close();
	}
	
	public static void main(String argv[]) throws Exception
	 {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		
		int option;
		String choice;
		String fileUID;
		String clientID;
		BufferedReader input = new BufferedReader(new InputStreamReader(System.in));
		SDFSClient2 client = new SDFSClient2();
		
		do
		{
			System.out.println("Menu");
			System.out.println("1. Connect to server");
			System.out.println("2. Put a file");
			System.out.println("3. Get a file");
			System.out.println("4. Delegate role");
			System.out.println("5. Terminate session");
			System.out.println("Enter option");
			option = Integer.parseInt(input.readLine());
			
			switch(option)
			{
			case 1:	//Connect to server
				client.startFSSession("localhost", 6789);
//				client.sendCert();
				break;
				
			case 2:	//Put a file
				System.out.print("Enter filename: ");
				fileUID = input.readLine();
				client.putFile(fileUID);
				break;
				
			case 3:	//Get a file
				System.out.print("Enter filename: ");
				fileUID = input.readLine();
				client.getFile(fileUID);
				break;
				
			case 4:	//Delegate role
				System.out.print("Enter client ID: ");
				clientID = input.readLine();
				client.delegate(clientID);
				break;
				
			case 5:	//Terminate session
				client.endSession();
				break;
				
			default: System.out.println("Invalid option. Retry.");
			}
			
			System.out.print("Do you wish to continue (Y/n)?");
			choice = input.readLine();
		}
		while(choice.equalsIgnoreCase("y"));
		
//		client.putFile("hello_cert");
//		client.getFile("test");
		client.endSession();
	 }

}
