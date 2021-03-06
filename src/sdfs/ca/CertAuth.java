package sdfs.ca;

import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.x509.X509V1CertificateGenerator;

/**
 * Certificate Authority
 * @author rohit
 *
 */

@SuppressWarnings("deprecation")
public class CertAuth {
	
	private static int numberOfInstance=0;
	@SuppressWarnings("unused")
	private static KeyPair CA_pair;
	
	protected CertAuth() throws NoSuchAlgorithmException, NoSuchProviderException
	{
		
		if(numberOfInstance == 0) 
		{
			new CertAuth();
			numberOfInstance++;
			
			KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
	        kpGen.initialize(1024, new SecureRandom());
	    	CA_pair = kpGen.generateKeyPair();
		}
		else
		{
			System.out.println("Cannot have more than one CA!");
		}
	}
	
	/**
	 * Writes the generated X509Certificate to disk
	 * @param subjectName
	 * @param cert
	 * @throws CertificateEncodingException
	 * @throws IOException
	 */
	
	private static void writeCert(String subjectName, X509Certificate cert) throws CertificateEncodingException, IOException
	{
		PEMWriter pemWrt = new PEMWriter(new BufferedWriter(new FileWriter("./src/sdfs/ca/certs/" + subjectName+".cert")));
		pemWrt.writeObject(cert);
		pemWrt.close();
	}
	
	/**
	 * Internal entities of the certificate to be generated
	 * @param subjectName
	 * @param pair
	 * @return X509Certificate
	 * @throws InvalidKeyException
	 * @throws NoSuchProviderException
	 * @throws SecurityException
	 * @throws SignatureException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateEncodingException
	 * @throws IOException
	 */
	public static X509Certificate generateCert(String subjectName, KeyPair pair) throws InvalidKeyException, NoSuchProviderException, SecurityException, SignatureException, NoSuchAlgorithmException, CertificateEncodingException, IOException
	{
		
		// Generate the certificate
        X509V1CertificateGenerator  certGen = new X509V1CertificateGenerator();

        certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        certGen.setIssuerDN(new X509Name("CN=Certificate Authority"));
        certGen.setNotBefore(new Date(System.currentTimeMillis() - 50000));
        certGen.setNotAfter(new Date(System.currentTimeMillis() + 100000));
        certGen.setSubjectDN(new X509Name("CN="+subjectName));
        certGen.setPublicKey(pair.getPublic());
        certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
        
        writeCert(subjectName, certGen.generateX509Certificate(pair.getPrivate(), "BC"));
		return certGen.generateX509Certificate(pair.getPrivate(), "BC");
	}

	/**
	 * Reads the contents of the specified certificate
	 * @param f
	 * @return X509Certificate
	 * @throws CertificateException
	 * @throws NoSuchProviderException
	 * @throws IOException
	 */
	
	public static X509Certificate readCert(File f) throws CertificateException, NoSuchProviderException, IOException
	{	
		byte[] b;
		try
		{
			FileInputStream cert_f = new FileInputStream("./src/sdfs/ca/" + f.getName());
			b = new byte[(int)cert_f.available()];
			cert_f.read(b);
			cert_f.close();
			
		}
		catch (IOException e)
		{
			System.out.println("The certificate doesn't exist for this node.");
			return null;
		}
		
		InputStream in = new ByteArrayInputStream(b);
		CertificateFactory fact = CertificateFactory.getInstance("X.509","BC");
	    return  (X509Certificate)fact.generateCertificate(in);
	 }
	
	/**
	 * Validates the client certificate
	 * @param f
	 * @throws NoSuchProviderException
	 * @throws IOException
	 * @throws CertificateException
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws SignatureException
	 */
	
	public static void checkCertStatus(File f) throws NoSuchProviderException, IOException, CertificateException, InvalidKeyException, NoSuchAlgorithmException, SignatureException
	{
		X509Certificate cert = readCert(f);
		try
		{
			cert.checkValidity(new Date());
			cert.verify(cert.getPublicKey());
		}
		catch (NullPointerException e)
		{
			return;
		}
		System.out.println("Certificate for node "+ cert.getSubjectX500Principal().getName().substring(3) +" is valid.");
	}
	
}
