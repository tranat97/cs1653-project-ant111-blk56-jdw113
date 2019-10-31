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
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.File;
import java.io.IOException;

public class Crypto
{
	public Crypto()
	{
		Security.addProvider(new BouncyCastleProvider());
	}

	public byte[] hash(String s)
	{
		try
		{
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			return md.digest(s.getBytes());
		}
		catch (GeneralSecurityException e)
		{
			System.err.println("Failed to hash");
			e.printStackTrace();
			return null;
		}
	}

	public byte[] sign(PrivateKey privateKey, byte[] plaintext)
	{
		try
		{
			final Signature sig = Signature.getInstance("SHA256withRSA", "BC");
			sig.initSign(privateKey);
			sig.update(plaintext);
			return sig.sign();
		}
		catch (GeneralSecurityException e)
		{
			System.err.println("Failed to sign");
			e.printStackTrace();
			return null;
		}
	}

	public boolean verify(PublicKey publicKey, byte[] ciphertext, byte[] plaintext)
	{
		try
		{
			final Signature sig = Signature.getInstance("SHA256withRSA", "BC");
			sig.initVerify(publicKey);
			sig.update(plaintext);
			return sig.verify(ciphertext);
		}
		catch (GeneralSecurityException e)
		{
			System.err.println("Failed to verify");
			e.printStackTrace();
			return false;
		}
	}

	public byte[] encryptAESKey(Key AESKey, Key publicKey)
	{
		try
		{
			final Cipher cipher = Cipher.getInstance("RSA", "BC");
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			return cipher.doFinal(AESKey.getEncoded());
		}
		catch (GeneralSecurityException e)
		{
			System.err.println("Failed to decrypt AES key");
			e.printStackTrace();
			return null;
		}
	}

	public Key decryptAESKey(byte[] ciphertext, Key privateKey)
	{
		try
		{
			final Cipher cipher = Cipher.getInstance("RSA", "BC");
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			final byte plaintext[] = cipher.doFinal(ciphertext);
			return new SecretKeySpec(plaintext, "AES");
		}
		catch (GeneralSecurityException e)
		{
			System.err.println("Failed to decrypt AES key");
			e.printStackTrace();
			return null;
		}
	}

	public byte[] decrypt(byte[] ciphertext, byte IVBytes[], Key k)
	{
		try
		{
			final IvParameterSpec IV = new IvParameterSpec(IVBytes);
			final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, k, IV);
			return cipher.doFinal(ciphertext);
		}
		catch (GeneralSecurityException e)
		{
			System.err.println("Failed to decrypt");
			e.printStackTrace();
			return null;
		}
	}

	public byte[] encrypt(byte[] plaintext, byte IVBytes[], Key k)
	{
		try
		{
			final IvParameterSpec IV = new IvParameterSpec(IVBytes);
			final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, k, IV);
			return cipher.doFinal(plaintext);
		}
		catch (GeneralSecurityException e)
		{
			System.err.println("Failed to encrypt");
			e.printStackTrace();
			return null;
		}
	}

	public byte[] generateIV()
	{
		final SecureRandom rand = new SecureRandom();
		final byte IV[] = new byte[16];
		rand.nextBytes(IV);
		return IV;
	}

	public Key generateAESKey()
	{
		try
		{
			final KeyGenerator keygen = KeyGenerator.getInstance("AES", "BC");
			keygen.init(256);
			return keygen.generateKey();
		}
		catch (GeneralSecurityException e)
		{
			System.err.println("Failed to generate AES key");
			e.printStackTrace();
			return null;
		}
	}

	public KeyPair generateRSAKeys() 
	{
		try
		{
			final KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA", "BC");
			keygen.initialize(4096);
			return keygen.generateKeyPair();
		}
		catch (GeneralSecurityException e)
		{
			System.err.println("Failed to generate RSA keypair");
			e.printStackTrace();
			return null;
		}
	}

	public KeyPair getRSAKeys(final String publicPath, final String privatePath)
	{
		final File publicFile = new File(publicPath);
		final File privateFile = new File(privatePath);
		KeyPair RSAKeys = null;

		// if keys already exist
		if (publicFile.exists() && privateFile.exists())
		{
			try
			{
				FileInputStream fis = new FileInputStream(publicFile);
				ObjectInputStream ois = new ObjectInputStream(fis);
				final PublicKey pub = (PublicKey)ois.readObject();
				ois.close();
				fis.close();

				fis = new FileInputStream(privateFile);
				ois = new ObjectInputStream(fis);
				final PrivateKey priv = (PrivateKey)ois.readObject();
				ois.close();
				fis.close();

				RSAKeys = new KeyPair(pub, priv);
				System.out.println("RSA key pair found");
			}
			catch (IOException e)
			{
				System.err.println("Error reading existing keys");
				return null;
			}
			catch (ClassNotFoundException e)
			{
				System.err.println("Error reading existing keys");
				return null;
			}
		}
		else
		{
			System.out.println("RSA key pair not found, generating...");
			RSAKeys = generateRSAKeys();
			if (RSAKeys == null)
			{
				return null;
			}

			try
			{
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
			}
			catch (IOException e)
			{
				System.err.println("Error writing new keys");
			}
		}
		return RSAKeys;
	}
}
