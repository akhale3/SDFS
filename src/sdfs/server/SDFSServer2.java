package sdfs.server;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

import org.bouncycastle.openssl.PEMWriter;

import sdfs.ca.CertAuth;

public class SDFSServer2{

	private DataInputStream inFromClient = null;
	private DataOutputStream outToClient = null;
	private static FileInputStream fileIS = null;
	private FileOutputStream fileOS = null;
	
	private SSLServerSocketFactory sslSockFact = null;
	private SSLServerSocket server = null;
	private SSLSocket serverSocket = null;
	
	void startFSSession() throws IOException, CertificateException, NoSuchProviderException, InterruptedException
	{
		sslSockFact = (SSLServerSocketFactory)SSLServerSocketFactory.getDefault();
		server = (SSLServerSocket)sslSockFact.createServerSocket(6789);
		System.out.println("Status: Awaiting connection ...");
		serverSocket = (SSLSocket)server.accept();
		
		inFromClient = new DataInputStream(serverSocket.getInputStream());
		outToClient = new DataOutputStream(serverSocket.getOutputStream());
		
		System.out.println("Receiving client certificate ...");
		CertificateFactory fact_client = CertificateFactory.getInstance("X.509", "BC");
		X509Certificate clientCert = null;
		try
		{
			clientCert = (X509Certificate)fact_client.generateCertificate(inFromClient);
		}
		catch (Exception e1)
		{
			e1.printStackTrace();
		}
		System.out.println("Client's certificate received");
		
		try
		{
        	CertAuth.checkCertStatus(clientCert.getSubjectX500Principal().getName());
        }
		catch (Exception e)
		{
			System.out.println("Wrong certificate provided! Closing connection ...");
			endFSSession();
			return;
		}
		System.out.println("Client's certificate verified");
        
        System.out.println("Sending server certificate to client ...");
        PEMWriter pemWrt = new PEMWriter(new OutputStreamWriter(outToClient));
		pemWrt.writeObject(CertAuth.readCert("server_cert"));
		pemWrt.close();
        System.out.println("Connection Established");
	}
	
	void getFile() throws IOException
	{
		int length;
		Long fileLength;
		byte[] buffer;
		Path filePath = FileSystems.getDefault().getPath("./test_recv");
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
		fileIS.close();
		outToClient.close();
		inFromClient.close();
		serverSocket.close();
	}
	
	public static void main(String args[]) throws Exception
      {
		SDFSServer2 serv = new SDFSServer2();
		serv.startFSSession();
		serv.getFile();
		serv.endFSSession();
      }
}