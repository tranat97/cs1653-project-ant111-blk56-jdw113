import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.Key;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.MessageDigest;
import java.security.Security;
import java.security.SecureRandom;
import java.security.GeneralSecurityException;
import javax.crypto.KeyGenerator;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.util.*;
import java.math.BigInteger;

public class Crypto implements java.io.Serializable
{
	public Crypto()
	{
		Security.addProvider(new BouncyCastleProvider());
	}

	/* Returns an envelope with encrypted contents using our format */
	public Envelope encrypt(Envelope e, int messageNumber, Key AESKey, Key HMACKey)
	{
		byte[] IV = generateRandomBytes(16);
		Envelope result = new Envelope(bytesToHex(encrypt(e.getMessage().getBytes(), IV, AESKey)));
		result.addObject(Arrays.copyOf(IV, IV.length));
		for (int i = 0; i < e.getObjContents().size(); i++) {
			IV[0]++;
			Object contents = e.getObjContents().get(i);
			if (contents == null) {
				result.addObject(null);
			} else {
				result.addObject(encrypt(objectToBytes(contents), IV, AESKey));
			}
		}
		// calculate and store HMAC in envelope
		// HMAC is of the encrypted contents, and we
		// will not be encrypting the HMAC
		result.setHMAC(hmac(result, messageNumber, HMACKey));
		return result;
	}

	/* Returns an envelope with decrypted contents using our format
	   If the HMAC is bad, then we return null */
	public Envelope decrypt(Envelope e, int messageNumber, Key AESKey, Key HMACKey)
	{
		// calculate and verify HMAC
		byte[] hmac = hmac(e, messageNumber, HMACKey);
		if (!Arrays.equals(hmac, e.getHMAC())) {
			return null;
		}

		byte[] IV = (byte[]) e.getObjContents().get(0);
		Envelope result = new Envelope(new String(decrypt(hexToBytes(e.getMessage()), IV, AESKey)));
		for (int i = 1; i < e.getObjContents().size(); i++) {
			IV[0]++;
			byte[] contents = (byte[]) e.getObjContents().get(i);
			if (contents == null) {
				result.addObject(null);
			} else {
				result.addObject(bytesToObject(decrypt(contents, IV, AESKey)));
			}
		}
		return result;
	}

	public byte[] hmac(Envelope e, int messageNumber, Key HMACKey)
	{
		try {
			Mac mac = Mac.getInstance("HmacSHA256", "BC");
			mac.init(HMACKey);
			// using BigInteger to convert int to byte[]
			mac.update(BigInteger.valueOf(messageNumber).toByteArray());
			mac.update(e.getMessage().getBytes());
			for (int i = 0; i < e.getObjContents().size(); i++) {
				mac.update((byte[]) e.getObjContents().get(i));
			}
			byte[] result = mac.doFinal();
			return result;
		} catch (GeneralSecurityException ex) {
			System.err.println("Failed to calculate HMAC");
			ex.printStackTrace();
			return null;
		}
	}

	public byte[] hash(byte[] plaintext)
	{
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256", "BC");
			return md.digest(plaintext);
		} catch (GeneralSecurityException e) {
			System.err.println("Failed to hash");
			e.printStackTrace();
			return null;
		}
	}

	public void sign(PrivateKey privateKey, UserToken token)
	{
		token.setSignature(sign(privateKey, token.toString().getBytes()));
	}

	public byte[] sign(PrivateKey privateKey, byte[] plaintext)
	{
		try {
			final Signature sig = Signature.getInstance("SHA256withRSA", "BC");
			sig.initSign(privateKey);
			sig.update(plaintext);
			return sig.sign();
		} catch (GeneralSecurityException e) {
			System.err.println("Failed to sign");
			e.printStackTrace();
			return null;
		}
	}

	public boolean verify(PublicKey publicKey, UserToken token)
	{
		return verify(publicKey, token.getSignature(), token.toString().getBytes());
	}

	public boolean verify(PublicKey publicKey, byte[] ciphertext, byte[] plaintext)
	{
		try {
			final Signature sig = Signature.getInstance("SHA256withRSA", "BC");
			sig.initVerify(publicKey);
			sig.update(plaintext);
			return sig.verify(ciphertext);
		} catch (GeneralSecurityException e) {
			System.err.println("Failed to verify");
			e.printStackTrace();
			return false;
		}
	}

	public byte[] rsaEncrypt(byte[] plaintext, Key publicKey)
	{
		try {
			final Cipher cipher = Cipher.getInstance("RSA", "BC");
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			return cipher.doFinal(plaintext);
		} catch (GeneralSecurityException e) {
			System.err.println("Failed to encrypt plaintext");
			e.printStackTrace();
			return null;
		}
	}

	public byte[] rsaDecrypt(byte[] ciphertext, Key privateKey)
	{
		try {
			final Cipher cipher = Cipher.getInstance("RSA", "BC");
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			return cipher.doFinal(ciphertext);
			//return new SecretKeySpec(plaintext, "AES");
		} catch (GeneralSecurityException e) {
			System.err.println("Failed to decrypt plaintext");
			e.printStackTrace();
			return null;
		}
	}

	public byte[] decrypt(byte[] ciphertext, byte IVBytes[], Key k)
	{
		try {
			final IvParameterSpec IV = new IvParameterSpec(IVBytes);
			final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
			cipher.init(Cipher.DECRYPT_MODE, k, IV);
			return cipher.doFinal(ciphertext);
		} catch (GeneralSecurityException e) {
			System.err.println("Failed to decrypt");
			e.printStackTrace();
			return null;
		}
	}

	public byte[] encrypt(byte[] plaintext, byte IVBytes[], Key k)
	{
		try {
			final IvParameterSpec IV = new IvParameterSpec(IVBytes);
			final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
			cipher.init(Cipher.ENCRYPT_MODE, k, IV);
			return cipher.doFinal(plaintext);
		} catch (GeneralSecurityException e) {
			System.err.println("Failed to encrypt");
			e.printStackTrace();
			return null;
		}
	}


	public Key generateAESKey()
	{
		try {
			final KeyGenerator keygen = KeyGenerator.getInstance("AES", "BC");
			keygen.init(256);
			return keygen.generateKey();
		} catch (GeneralSecurityException e) {
			System.err.println("Failed to generate AES key");
			e.printStackTrace();
			return null;
		}
	}

	public KeyPair generateRSAKeys() 
	{
		try {
			final KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA", "BC");
			keygen.initialize(4096);
			return keygen.generateKeyPair();
		} catch (GeneralSecurityException e) {
			System.err.println("Failed to generate RSA keypair");
			e.printStackTrace();
			return null;
		}
	}
	
	public byte[] generateRandomBytes(int n) {
		final SecureRandom rand = new SecureRandom();
		final byte randBytes[] = new byte[n];
		rand.nextBytes(randBytes);
		return randBytes;
	}

	public PublicKey getPublicKey(final String publicPath)
	{
		final File publicFile = new File(publicPath);
		if (publicFile.exists()) {
			try {
				FileInputStream fis = new FileInputStream(publicFile);
				ObjectInputStream ois = new ObjectInputStream(fis);
				final PublicKey pub = (PublicKey)ois.readObject();
				ois.close();
				fis.close();
				return pub;
			} catch (Exception e) {
				System.err.println("Error reading existing public key");
				e.printStackTrace();
			}
		} 
		return null;
	}

	public PrivateKey getPrivateKey(final String privatePath)
	{
		final File privateFile = new File(privatePath);
		if (privateFile.exists()) {
			try {
				FileInputStream fis = new FileInputStream(privateFile);
				ObjectInputStream ois = new ObjectInputStream(fis);
				final PrivateKey priv = (PrivateKey)ois.readObject();
				ois.close();
				fis.close();
				return priv;
			} catch (Exception e) {
				System.err.println("Error reading existing private key");
				e.printStackTrace();
			}
		}
		return null;
	}

	public KeyPair getRSAKeys(final String publicPath, final String privatePath)
	{
		final File publicFile = new File(publicPath);
		final File privateFile = new File(privatePath);
		final PublicKey pub = getPublicKey(publicPath);
		final PrivateKey priv = getPrivateKey(privatePath);
		KeyPair RSAKeys = null;

		// if keys already exist
		if (pub != null && priv != null) {
			RSAKeys = new KeyPair(pub, priv);
			System.out.println("RSA key pair found");
		} else {
			System.out.println("RSA key pair not found, generating...");
			RSAKeys = generateRSAKeys();
			if (RSAKeys == null) {
				return null;
			}

			try {
				// writing new keypair to files
				FileOutputStream fos = new FileOutputStream(publicFile);
				ObjectOutputStream oos = new ObjectOutputStream(fos);
				oos.writeObject(RSAKeys.getPublic());
				oos.close();
				fos.close();

				fos = new FileOutputStream(privateFile);
				oos = new ObjectOutputStream(fos);
				oos.writeObject(RSAKeys.getPrivate());
				oos.close();
				fos.close();
				System.out.println("Saved keys to files");
			} catch (IOException e) {
				System.err.println("Error writing new keys");
			}
		}
		return RSAKeys;
	}

	public byte[] hexToBytes(String hex)
	{
		return DatatypeConverter.parseHexBinary(hex);
	}

	public String bytesToHex(byte[] bytes)
	{
		return DatatypeConverter.printHexBinary(bytes);
	}

	public String fingerprint(Key k)
	{
		return bytesToHex(hash(k.getEncoded()));
	}

	private Object bytesToObject(byte[] bytes)
	{
		try {
			final ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
			final ObjectInputStream ois = new ObjectInputStream(bis);
			final Object o = ois.readObject();
			ois.close();
			bis.close();
			return o;
		} catch (Exception e) {
			System.err.println("Failed to turn bytes into token");
			e.printStackTrace();
			return null;
		}
	}

	private byte[] objectToBytes(Object o)
	{
		try {
			final ByteArrayOutputStream bos = new ByteArrayOutputStream();
			final ObjectOutputStream oos = new ObjectOutputStream(bos);
			oos.writeObject(o);
			oos.flush();
			final byte[] bytes = bos.toByteArray();
			oos.close();
			bos.close();
			return bytes;
		} catch (Exception e) {
			System.err.println("Failed to turn token into bytes");
			e.printStackTrace();
			return null;
		}
	}
}
