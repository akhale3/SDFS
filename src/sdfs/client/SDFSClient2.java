package sdfs.client;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
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

public class SDFSClient2 {
	
	private InputStream inFromServer = null;
	private OutputStream outToServer = null;
	private static FileInputStream fileIS = null;
	
	private SSLSocketFactory sslFact = null;
	private SSLSocket clientSocket = null;
	
	private final String[] enabledCipherSuites = { "SSL_DH_anon_WITH_RC4_128_MD5" };
	
	Path computeFilePath(String fileUID)
	{
		Path filePath;
		filePath = FileSystems.getDefault().getPath("./", "src", "sdfs", "client", fileUID);
		return filePath;
	}
	
	void getFile(String fileUID) throws UnknownHostException, IOException
	{
		
	}
	
	boolean putFile(String fileUID) throws IOException
	{
		int length;
		String fileName;
		Long fileLength;
		Path filePath = computeFilePath(fileUID);
		File file = new File(filePath.toString());
		if(file.exists())
		{
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
			return true;
		}
		else
		{
			System.out.println(fileUID + " does not exist");
			System.out.println("Acquiring client certificate ...");
			return false;
		}
	}
	
	void delegate()
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
		outToServer.close();
		inFromServer.close();
		clientSocket.close();
	}
	
	public static void main(String argv[]) throws Exception
	 {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		SDFSClient2 client = new SDFSClient2();
		client.startFSSession("localhost", 6789);
//		client.sendCert();
//		client.putFile("hello_cert");
		client.endSession();
	 }

}
