package sdfs.server;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import org.bouncycastle.util.encoders.Base64;


/**
 * has the enc/dec functions for server!!
 * @author rohit
 *
 */
public class SDFSServerFn {

	private static int noOfInstances=0;
	private KeyPair pair;
    private KeyPairGenerator generator;
//	private static X509Certificate serverCert;
    private static Cipher cipher;
    private static Key pubKey;
    private static Key privKey;
    
    SDFSServerFn() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, NoSuchPaddingException
     {
    	if (noOfInstances==0)
    	{
    		cipher = Cipher.getInstance("RSA/None/NoPadding", "BC");
    		generator = KeyPairGenerator.getInstance("RSA", "BC");
	    	pair = generator.generateKeyPair();
	    	pubKey = pair.getPublic();
	    	privKey = pair.getPrivate();
    	
    	//       	 storeKeys(); ?? -- is there a need
    	}
    	else
    	{
    		System.out.println("This scheme only supports single server!");
    		System.exit(-1);
    	}
     }
     
    /**Computes path of file
     * 
     * @param fileUID
     * @return
     */
    
    Path computeFilePath(String fileName)
	{
		Path filePath;
		filePath = FileSystems.getDefault().getPath("./", "src", "sdfs", "server", fileName);
//		filePath = FileSystems.getDefault().getPath(fileName);
		return filePath;
	}
    
    /**converts byte[] of ASCII characters to hex and returns as a string
	 * 
	 * @param data
	 * @param length
	 * @return
	 */
    private static String toHex(byte[] data, int length)
    {
        StringBuffer    buf = new StringBuffer();
        for (int i = 0; i != length; i++)
        {
            int v = data[i] & 0xff;
            buf.append("0123456789abcdef".charAt(v>>4));
            buf.append("0123456789abcdef".charAt(v & 0xf));
        }
        return buf.toString();
    }

	/**opens the file "fileName", hashes its contents, encrypts the content using server's
	public key and stores it in "fileName_meta" file.
	 * @param fileName
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws ShortBufferException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 * @throws IOException
	 */
	protected void generateMetaFile(String fileName) throws NoSuchAlgorithmException, InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, NoSuchPaddingException, IOException
	{
		Path filePath = computeFilePath(fileName);
		FileInputStream ip_f = new FileInputStream(filePath.toString());
		byte[] b = new byte[(int)ip_f.available()];
		ip_f.read(b);
		ip_f.close();
	
		MessageDigest md = MessageDigest.getInstance("MD5");
        Cipher cipher = Cipher.getInstance("RSA/None/NoPadding", "BC");
        byte[] hashedFileContent=md.digest(b);
        
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
        generator.initialize(hashedFileContent.length*8, new SecureRandom());
        
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        byte[] cipherText = cipher.doFinal(hashedFileContent);
        String encryptedString=new String(Base64.encode(cipherText));
        System.out.println("cipher: " + toHex(cipherText,cipherText.length));
        
    	File file1 = new File(filePath.toString()+"_meta");
    	Writer writer = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(file1), "UTF-8"));
    	writer.write(encryptedString);
    	writer.close();
        
	}
	
	/** Reads the content of "fileName", encrypts it using the server's public key 
	 * and writes the encrypted content back to "fileName"
	 * @param fileName
	 * @throws InvalidKeyException
	 * @throws ShortBufferException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 * @throws IOException
	 * @throws InvalidAlgorithmParameterException
	 */
	protected void encryptFile(String fileName) throws InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException, InvalidAlgorithmParameterException
	{
		Path filePath = computeFilePath(fileName);
		System.out.println(filePath.toString());
		FileInputStream ip_f = new FileInputStream(filePath.toString());
		byte[] b = new byte[(int)ip_f.available()];
		ip_f.read(b);
		ip_f.close();
	
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
        generator.initialize(b.length*8, new SecureRandom());
        
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        byte[] cipherText = cipher.doFinal(b);
        String encryptedString=new String(Base64.encode(cipherText));
        
    	File file1 = new File(filePath.toString());
    	Writer writer = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(file1), "UTF-8"));
    	writer.write(encryptedString);
    	writer.close();        
	}
	
	/**Converts a hex string to ASCII string
	 * 
	 * @param hex
	 * @return
	 */
	private String convertHexToString(String hex){
		 
		  StringBuilder sb = new StringBuilder();
		  StringBuilder temp = new StringBuilder();
	 
		  for( int i=0; i<hex.length()-1; i+=2 )
		  {
	 
			  String output = hex.substring(i, (i + 2));
			  int decimal = Integer.parseInt(output, 16);
			  sb.append((char)decimal);
			  temp.append(decimal);
		  }
		  
		  return sb.toString();
	  }
	
	/**Decrypts and returns the "fileName"'s content
	 * 
	 * @param fileName
	 * @throws InvalidKeyException
	 * @throws ShortBufferException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 * @throws IOException
	 * @throws InvalidAlgorithmParameterException
	 */
	protected String decryptFile(String fileName) throws InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException, InvalidAlgorithmParameterException
	{
		String line,text="";
		Path filePath = computeFilePath(fileName);
		BufferedReader br = new BufferedReader(new FileReader(filePath.toString()));
		while ((line = br.readLine()) != null) {
			text+=line;
		}
		System.out.println("text-read="+text);
		br.close();
		
		byte[] encryptedText = (Base64.decode(text));        
		cipher.init(Cipher.DECRYPT_MODE, privKey);
        byte[] plainText = cipher.doFinal(encryptedText);
        return convertHexToString(toHex(plainText,plainText.length));
	}
	
	/**opens the meta file for the "fileName" provided, decrypts the content using server's
	 * private key and returns the hashed content (which will be the enc/dec) key of file
	 * @param fileName
	 * @return
	 * @throws InvalidKeyException
	 * @throws ShortBufferException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 * @throws IOException
	 * @throws InvalidAlgorithmParameterException 
	 */
	@SuppressWarnings("unused")
	private String decryptMetaFile(String fileName) throws InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException, InvalidAlgorithmParameterException
	{
		Path filePath = computeFilePath(fileName);
		return decryptFile(filePath.toString()+"_meta");
	}

}
