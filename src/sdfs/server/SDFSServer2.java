package sdfs.server;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

import sdfs.ca.CertAuth;

/**
 * Server Program
 * @author anish
 *
 */

public class SDFSServer2{

	private InputStream inFromClient = null;
	private OutputStream outToClient = null;
	private FileInputStream fileIS = null;
	private FileOutputStream fileOS = null;
	
	private SSLServerSocketFactory sslSockFact = null;
	private SSLServerSocket server = null;
	private SSLSocket serverSocket = null;
	
	private BufferedReader input;
	
	private final String[] enabledCipherSuites = { "SSL_DH_anon_WITH_RC4_128_MD5" };
	
	/**
	 * Initiates a secure session with client over SSL
	 * @throws IOException
	 * @throws CertificateException
	 * @throws NoSuchProviderException
	 * @throws InterruptedException
	 */
	
	void startFSSession() throws IOException, CertificateException, NoSuchProviderException, InterruptedException
	{
		sslSockFact = (SSLServerSocketFactory)SSLServerSocketFactory.getDefault();
		server = (SSLServerSocket)sslSockFact.createServerSocket(6789);
		System.out.println("Status: Awaiting connection ...");
		
		server.setEnabledCipherSuites(enabledCipherSuites);
		
		serverSocket = (SSLSocket)server.accept();
		
		inFromClient = serverSocket.getInputStream();
		outToClient = serverSocket.getOutputStream();
		
		input = new BufferedReader(new InputStreamReader(inFromClient));

        System.out.println("Connection Established");
	}
	
	/**
	 * Verifies the validity of the client certificate
	 * @param file
	 * @throws InvalidKeyException
	 * @throws NoSuchProviderException
	 * @throws CertificateException
	 * @throws NoSuchAlgorithmException
	 * @throws SignatureException
	 * @throws IOException
	 */
	
	void invokeVerify(File file) throws InvalidKeyException, NoSuchProviderException, CertificateException, NoSuchAlgorithmException, SignatureException, IOException
	{
		CertAuth.checkCertStatus(file);
		System.out.println("Certificate Status: Valid");
	}
	
	/**
	 * Sets the directory path to ./src/sdfs/server
	 * @param fileUID
	 * @return filePath
	 */
	
	Path computeFilePath(String fileUID)
	{
		Path filePath;
		filePath = FileSystems.getDefault().getPath("./", "src", "sdfs", "server", fileUID);
		return filePath;
	}
	
	/**
	 * Sends a requested file to the client upon decryption
	 * @param fileUID
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws ShortBufferException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidAlgorithmParameterException
	 */
	
	void putFile(String fileUID) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException
	{
		int length;
		Path filePath = computeFilePath(fileUID);
		File file = new File(filePath.toString());
		
		if(file.exists())
		{
			SDFSServerFn sfn = new SDFSServerFn();
			sfn.decryptFile(fileUID);
			
			byte[] buffer = new byte[1024];
			fileIS = new FileInputStream(file);

			while ((length = fileIS.read(buffer)) > 0)
			{
				outToClient.write(buffer, 0, length);
			}
			outToClient.write('\n');
			outToClient.write("eof".getBytes());
			outToClient.write('\n');
		}
		else
		{
			System.out.println(fileUID + " does not exist");
		}
	}
	
	/**
	 * Receives a file from the client, creates meta data and stores it at filePath 
	 * @param fileUID
	 * @throws IOException
	 * @throws InvalidKeyException
	 * @throws NoSuchProviderException
	 * @throws CertificateException
	 * @throws NoSuchAlgorithmException
	 * @throws SignatureException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchPaddingException
	 * @throws ShortBufferException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidAlgorithmParameterException
	 */
	
	void getFile(String fileUID) throws IOException, InvalidKeyException, NoSuchProviderException, CertificateException, NoSuchAlgorithmException, SignatureException, InvalidKeySpecException, NoSuchPaddingException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException
	{
		int length;
		String fileName;
		String suffix;
		File file = null;
		Path filePath = null;
		String temp;
		fileName = fileUID;	

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

		if(suffix.equalsIgnoreCase("cert"))
		{
			file = new File(fileName);
			invokeVerify(file);
		}
		else
		{
			SDFSServerFn sfn = new SDFSServerFn();
			sfn.generateMetaFile(fileName);
			sfn.encryptFile(fileName);
		}
	}
	
	/**
	 * Terminates an established session
	 * @throws IOException
	 */
	
	void endFSSession() throws IOException
	{
		fileOS.close();
		fileIS.close();
		outToClient.close();
		inFromClient.close();
		serverSocket.close();
	}
	
	/**
	 * Receives commands "get" and "put" from client.
	 * "get" invokes getFile() while "put" invokes putFile().
	 * Any other command terminates the session.
	 * @throws IOException
	 * @throws InvalidKeyException
	 * @throws NoSuchProviderException
	 * @throws CertificateException
	 * @throws NoSuchAlgorithmException
	 * @throws SignatureException
	 * @throws InterruptedException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchPaddingException
	 * @throws ShortBufferException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidAlgorithmParameterException
	 */
	
	void getCommand() throws IOException, InvalidKeyException, NoSuchProviderException, CertificateException, NoSuchAlgorithmException, SignatureException, InterruptedException, InvalidKeySpecException, NoSuchPaddingException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException
	{
		String command;
		String fileUID;
		
		while(true)
		{
			command = input.readLine();
			System.out.println(command);
			switch(command)
			{
			case "put":
				fileUID = input.readLine();
				System.out.println(fileUID);
				putFile(fileUID);
				break;
				
			case "get":
				fileUID = input.readLine();
				System.out.println(fileUID);
				getFile(fileUID);
				break;
				
			default: endFSSession();
			}
		}
	}
	
	public static void main(String args[]) throws Exception
      {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		SDFSServer2 serv = new SDFSServer2();
		serv.startFSSession();
		serv.getCommand();
      }
}