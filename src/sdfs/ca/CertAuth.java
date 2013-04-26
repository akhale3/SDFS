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
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.x509.X509V1CertificateGenerator;

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
	
	private static void writeCert(String subjectName, X509Certificate cert) throws CertificateEncodingException, IOException
	{
		PEMWriter pemWrt = new PEMWriter(new BufferedWriter(new FileWriter("./src/sdfs/ca/certs/" + subjectName+".cert")));
		pemWrt.writeObject(cert);
		pemWrt.close();
	}
	
	
	public static X509Certificate generateCert(String subjectName, KeyPair pair) throws InvalidKeyException, NoSuchProviderException, SecurityException, SignatureException, NoSuchAlgorithmException, CertificateEncodingException, IOException
	{
		
		// generate the certificate
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
	
	
/*	public static void generateCert(String subjectName, PublicKey publicKey) throws InvalidKeyException, NoSuchProviderException, SecurityException, SignatureException, NoSuchAlgorithmException, CertificateEncodingException, IOException
	{
		
		X509V1CertificateGenerator  certGen = new X509V1CertificateGenerator();

        certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        certGen.setIssuerDN(new X509Name("CN=Certificate Authority"));
        certGen.setNotBefore(new Date(System.currentTimeMillis() - 50000));
        certGen.setNotAfter(new Date(System.currentTimeMillis() + 100000));
        certGen.setSubjectDN(new X509Name("CN="+subjectName));
        certGen.setPublicKey(publicKey);
        certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
        
        writeCert(subjectName, certGen.generateX509Certificate(CA_pair.getPrivate(), "BC"));
	}
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
	    
	    public static void main(String[] args)  throws Exception
	    {
	    	Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider()); //have this in the final main method()
	    	
	    	KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
	        kpGen.initialize(1024, new SecureRandom());
	    	@SuppressWarnings("unused")
			KeyPair pair = kpGen.generateKeyPair();
	       
//	        X509Certificate cert1 = dummy_generateCert("hello",pair);
//	        X509Certificate cert2 = dummy_generateCert("kitty",pair);
//	        System.out.println(cert1);
//	        System.out.println(cert2);
//	        System.out.println("--------------");
//	        checkCertStatus("hello");
//	        checkCertStatus("kitty");
	      }
	}
