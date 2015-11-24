package prove.sicurezza.iccrea;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class Provona {
	
	public void read() throws Exception{
		String path = "C:\\Sviluppo\\KEYSTORE";
		PrivateKey privateKey = LoadPrivateKey(path);
		String dataToSend = "This is the data to send....";
		Signature dsa = Signature.getInstance("SHA1withDSA", "SUN"); 
		dsa.initSign(privateKey);
		dsa.update(dataToSend.getBytes());
		byte[] realSig = dsa.sign();
		service(realSig, dataToSend);
	}
	
	public void service(byte[] sigToVerify, String data) throws Exception{
		System.out.println(sigToVerify);
		String path = "C:\\Sviluppo\\KEYSTORE";
		PublicKey publicKey = LoadPublicKey(path);
		Signature sig = Signature.getInstance("SHA1withDSA", "SUN");
		sig.initVerify(publicKey);
		sig.update(data.getBytes());
		boolean verifies = sig.verify(sigToVerify);

		System.out.println("signature verifies: " + verifies);
		
		//verificato che il chiamante è chi dice di essere devo tornargli le credenziali
		//criptandole con la chiave publica
		
	}
	
	public static void main(String[] aa) throws Exception{
		Provona p = new Provona();
		p.read();
	}

	public static void main2(String args[]) {
		Provona adam = new Provona();
		try {
			String path = "C:\\Sviluppo\\KEYSTORE";
 
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
			SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
			keyGen.initialize(1024, random);
			KeyPair pair = keyGen.generateKeyPair();
			adam.dumpKeyPair(pair);
			
//			PrivateKey priv = pair.getPrivate();
//			PublicKey pub = pair.getPublic();
//			
//			Signature dsa = Signature.getInstance("SHA1withDSA", "SUN"); 
//			dsa.initSign(priv);
			
			
			System.out.println("Generated Key Pair");
			adam.dumpKeyPair(pair);
			adam.SaveKeyPair(path, pair);
 
			KeyPair loadedKeyPair = adam.LoadKeyPair(path, "DSA");
			System.out.println("Loaded Key Pair");
			adam.dumpKeyPair(loadedKeyPair);
			
			
		} catch (Exception e) {
			e.printStackTrace();
			return;
		}
	}
 
	private void dumpKeyPair(KeyPair keyPair) {
		PublicKey pub = keyPair.getPublic();
		System.out.println("Public Key: " + getHexString(pub.getEncoded()));
 
		PrivateKey priv = keyPair.getPrivate();
		System.out.println("Private Key: " + getHexString(priv.getEncoded()));
	}
 
	private String getHexString(byte[] b) {
		String result = "";
		for (int i = 0; i < b.length; i++) {
			result += Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1);
		}
		return result;
	}
 
	public void SaveKeyPair(String path, KeyPair keyPair) throws IOException {
		PrivateKey privateKey = keyPair.getPrivate();
		PublicKey publicKey = keyPair.getPublic();
 
		// Store Public Key.
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
				publicKey.getEncoded());
		FileOutputStream fos = new FileOutputStream(path + "/public.key");
		fos.write(x509EncodedKeySpec.getEncoded());
		fos.close();
 
		// Store Private Key.
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
				privateKey.getEncoded());
		fos = new FileOutputStream(path + "/private.key");
		fos.write(pkcs8EncodedKeySpec.getEncoded());
		fos.close();
	}
 
	public KeyPair LoadKeyPair(String path, String algorithm)
			throws IOException, NoSuchAlgorithmException,
			InvalidKeySpecException {
		// Read Public Key.
		File filePublicKey = new File(path + "/public.key");
		FileInputStream fis = new FileInputStream(path + "/public.key");
		byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];
		fis.read(encodedPublicKey);
		fis.close();
 
		// Read Private Key.
		File filePrivateKey = new File(path + "/private.key");
		fis = new FileInputStream(path + "/private.key");
		byte[] encodedPrivateKey = new byte[(int) filePrivateKey.length()];
		fis.read(encodedPrivateKey);
		fis.close();
 
		// Generate KeyPair.
		KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
				encodedPublicKey);
		PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
 
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
				encodedPrivateKey);
		PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
 
		return new KeyPair(publicKey, privateKey);
	}
	
	
	public PublicKey LoadPublicKey(String path)
			throws IOException, NoSuchAlgorithmException,
			InvalidKeySpecException {
		// Read Public Key.
		File filePublicKey = new File(path + "/public.key");
		FileInputStream fis = new FileInputStream(path + "/public.key");
		byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];
		fis.read(encodedPublicKey);
		fis.close();
 
		// Generate KeyPair.
		KeyFactory keyFactory = KeyFactory.getInstance("DSA");
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
				encodedPublicKey);
		PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
 
		return publicKey;
	}
	
	
	public PrivateKey LoadPrivateKey(String path)
			throws IOException, NoSuchAlgorithmException,
			InvalidKeySpecException {
		// Read Private Key.
		File filePrivateKey = new File(path + "/private.key");
		FileInputStream fis = new FileInputStream(path + "/private.key");
		byte[] encodedPrivateKey = new byte[(int) filePrivateKey.length()];
		fis.read(encodedPrivateKey);
		fis.close();
 
		// Generate KeyPair.
		KeyFactory keyFactory = KeyFactory.getInstance("DSA");
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
				encodedPrivateKey);
		PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
 
		return privateKey;
	}

}
