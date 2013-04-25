package sdfs.ca;

import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
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
	private static KeyPair CA_pair;
	
	protected CertAuth() throws NoSuchAlgorithmException, NoSuchProviderException
	{
		
		if(numberOfInstance == 0) 
		{new CertAuth();
		numberOfInstance++;
		
		KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
        kpGen.initialize(1024, new SecureRandom());
    	CA_pair = kpGen.generateKeyPair();
		
		}
		else System.out.println("Cannot have more than one CA!");
	}
	
	private static void writeCert(String subjectName, X509Certificate cert) throws CertificateEncodingException, IOException
	{
		PEMWriter pemWrt = new PEMWriter(new BufferedWriter(new FileWriter(subjectName+"_cert")));
		pemWrt.writeObject(cert);
		pemWrt.close();
	}
	
	
	private static X509Certificate dummy_generateCert(String subjectName,KeyPair pair) throws InvalidKeyException, NoSuchProviderException, SecurityException, SignatureException, NoSuchAlgorithmException, CertificateEncodingException, IOException
	{
		
		// generate the certificate
        X509V1CertificateGenerator  certGen = new X509V1CertificateGenerator();

        certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
//        certGen.setIssuerDN(new X500Principal("CN=Certificate Authority"));
        certGen.setIssuerDN(new X509Name("CN=Certificate Authority"));
        certGen.setNotBefore(new Date(System.currentTimeMillis() - 50000));
        certGen.setNotAfter(new Date(System.currentTimeMillis() + 100000));
//        certGen.setSubjectDN(new X500Principal("CN="+subjectName));
        certGen.setSubjectDN(new X509Name("CN="+subjectName));
        certGen.setPublicKey(pair.getPublic());
        certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
        
        writeCert(subjectName, certGen.generateX509Certificate(pair.getPrivate(), "BC"));
		return certGen.generateX509Certificate(pair.getPrivate(), "BC");
	}
	
	
	@SuppressWarnings("unused")
	private static void generateCert(String subjectName,PublicKey publicKey) throws InvalidKeyException, NoSuchProviderException, SecurityException, SignatureException, NoSuchAlgorithmException, CertificateEncodingException, IOException
	{
		
		X509V1CertificateGenerator  certGen = new X509V1CertificateGenerator();

        certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
//        certGen.setIssuerDN(new X500Principal("CN=Certificate Authority"));
        certGen.setIssuerDN(new X509Name("CN=Certificate Authority"));
        certGen.setNotBefore(new Date(System.currentTimeMillis() - 50000));
        certGen.setNotAfter(new Date(System.currentTimeMillis() + 100000));
//        certGen.setSubjectDN(new X500Principal("CN="+subjectName));
        certGen.setSubjectDN(new X509Name("CN="+subjectName));
        certGen.setPublicKey(publicKey);
        certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
        
        writeCert(subjectName, certGen.generateX509Certificate(CA_pair.getPrivate(), "BC"));
	}

	public static X509Certificate readCert(String cert_name) throws CertificateException, NoSuchProviderException, IOException
	{	byte[] b;
		RandomAccessFile cert_file;
		try
		{
			cert_file = new RandomAccessFile(cert_name, "r");
			b = new byte[(int)cert_file.length()];
			cert_file.read(b);
			cert_file.close();
			
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
	
	public static void checkCertStatus(String subjectName) throws NoSuchProviderException, IOException, CertificateException, InvalidKeyException, NoSuchAlgorithmException, SignatureException
	{
		X509Certificate cert=readCert(subjectName+"_cert");
		try
		{
			cert.checkValidity(new Date());
			cert.verify(cert.getPublicKey());
		}
		catch (NullPointerException e)
		{
			return;
		}
		System.out.println("Certificate for node "+subjectName+" is valid.");
	}
	    
	    public static void main(String[] args)  throws Exception
	    {
	    	Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider()); //have this in the final main method()
	    	
	    	KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
	        kpGen.initialize(1024, new SecureRandom());
	    	KeyPair pair = kpGen.generateKeyPair();
	       
	        X509Certificate cert1 = dummy_generateCert("hello",pair);
	        X509Certificate cert2 = dummy_generateCert("kitty",pair);
	        System.out.println(cert1);
	        System.out.println(cert2);
	        System.out.println("--------------");
	        checkCertStatus("hello");
	        checkCertStatus("kitty");
	      }
	}
