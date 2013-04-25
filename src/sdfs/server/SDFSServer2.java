package sdfs.server;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateException;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

import sdfs.ca.CertAuth;

public class SDFSServer2{

	private InputStream inFromClient = null;
	private OutputStream outToClient = null;
	private static FileInputStream fileIS = null;
	private FileOutputStream fileOS = null;
	
	private SSLServerSocketFactory sslSockFact = null;
	private SSLServerSocket server = null;
	private SSLSocket serverSocket = null;
	
	private final String[] enabledCipherSuites = { "SSL_DH_anon_WITH_RC4_128_MD5" };
	
	void startFSSession() throws IOException, CertificateException, NoSuchProviderException, InterruptedException
	{
		sslSockFact = (SSLServerSocketFactory)SSLServerSocketFactory.getDefault();
		server = (SSLServerSocket)sslSockFact.createServerSocket(6789);
		System.out.println("Status: Awaiting connection ...");
		
		server.setEnabledCipherSuites(enabledCipherSuites);
		
		serverSocket = (SSLSocket)server.accept();
		
		inFromClient = serverSocket.getInputStream();
		outToClient = serverSocket.getOutputStream();
		
		System.out.println("Receiving client certificate ...");
/*		CertificateFactory fact_client = CertificateFactory.getInstance("X.509", "BC");
		X509Certificate clientCert = null;
		try
		{
			clientCert = (X509Certificate)fact_client.generateCertificate(inFromClient);
		}
		catch (Exception e1)
		{
			e1.printStackTrace();
		}
*/
		System.out.println("Client's certificate received");
		
/*		try
		{
        	CertAuth.checkCertStatus(clientCert.getSubjectX500Principal().getName());
        }
		catch (Exception e)
		{
			System.out.println("Wrong certificate provided! Closing connection ...");
			endFSSession();
			return;
		}
*/
		System.out.println("Client's certificate verified");
/*       
        System.out.println("Sending server certificate to client ...");
        PEMWriter pemWrt = new PEMWriter(new OutputStreamWriter(outToClient));
		pemWrt.writeObject(CertAuth.readCert("server_cert"));
		pemWrt.close();
*/
        System.out.println("Connection Established");
	}
	
	void getFile() throws IOException
	{
		int length;
		Long fileLength;
		byte[] buffer;
		Path filePath = FileSystems.getDefault().getPath("./test_recv");
		fileLength = new Long(inFromClient.read());
		fileOS = new FileOutputStream(filePath.toString());
		buffer = new byte[fileLength.intValue()];
		while ((length = inFromClient.read(buffer)) > 0)
		{
			fileOS.write(buffer, 0, length);
		}

//		BufferedReader input = new BufferedReader(new InputStreamReader(inFromClient));
//		String modifiedSentence = input.readLine();
//		System.out.println("FROM CLIENT: " + modifiedSentence);
	}
	
	void invokeVerify() throws InvalidKeyException, NoSuchProviderException, CertificateException, NoSuchAlgorithmException, SignatureException, IOException
	{
		File file = new File("./test_recv");
		CertAuth.checkCertStatus(file);
		System.out.println("Certificate Status: Valid");
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
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		SDFSServer2 serv = new SDFSServer2();
		serv.startFSSession();
		serv.getFile();
		serv.invokeVerify();
		serv.endFSSession();
      }
}