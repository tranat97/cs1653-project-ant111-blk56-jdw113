/* FileClient provides all the client functionality regarding the file server */
import java.io.*;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.*;
import java.security.PublicKey;

public class FileClient extends Client implements FileClientInterface
{
    Hashtable<String, byte[]> knownKeys;
	public FileClient()
	{
		crypto = new Crypto();
        knownKeys = null;
	}
	//Authentication of the File Server
	public boolean handshake()
	{
		String ans = null;
		Envelope message = null, response = null;
		Scanner in = new Scanner(System.in);
		byte[] r1 = null, r2 = null;
		try {			
			response = (Envelope) input.readObject();
			if (!response.getMessage().equals("PUBKEY") || response.getObjContents().size() != 1) {
				return false;
			}
			//extract public key, hash it and display
			serverPublicKey = (PublicKey) response.getObjContents().get(0);
			System.out.println("File Server Public Key: "+crypto.bytesToHex(crypto.hash(serverPublicKey.getEncoded())));
			do {
				System.out.print("Do you trust this key? (y/n): ");
				ans = in.next();
				if (ans.toLowerCase().equals("n")) {
					return false;
				}
			} while (!ans.toLowerCase().equals("y"));
			
			//CHALLENGE START
			//generate values
			AESKey = crypto.generateAESKey();
			r1 = crypto.generateRandomBytes(32);
			//System.out.println("R1 = "+(new String(r1)));
			//encrypt envelope using rsa
			message = new Envelope("R1");
			message.addObject(crypto.rsaEncrypt(r1, serverPublicKey));
			message.addObject(crypto.rsaEncrypt(AESKey.getEncoded(), serverPublicKey));
			output.writeObject(message);
			//Recieve R2 validate R1
			response = crypto.decrypt((Envelope) input.readObject(), AESKey);
			r2 = (byte[])response.getObjContents().get(0);
			if (!response.getMessage().equals("R2") || response.getObjContents().size()!=2 || !Arrays.equals(r1, r2)) {
				throw new Exception("Challenge 1 failure");
			}
			//Challenge 2 Response
			r2 = (byte[])response.getObjContents().get(1);
			//System.out.println("R2 = "+(new String(r2)));
			message = new Envelope("R2_RESPONSE");
			message.addObject(r2);
			output.writeObject(crypto.encrypt(message, AESKey));
			//Recieve OK message
			response = crypto.decrypt((Envelope)input.readObject(), AESKey);
			if (!response.getMessage().equals("OK") || response.getObjContents().size()!=0) {
				throw new Exception("Challenge 2 failure");
			}
			
			return true;
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}
	
	public boolean delete(String filename, UserToken token)
	{
		String remotePath;
		if (filename.charAt(0)=='/') {
			remotePath = filename.substring(1);
		} else {
			remotePath = filename;
		}
		Envelope env = new Envelope("DELETEF"); //Success
		env.addObject(remotePath);
		env.addObject(token);
		try {
			output.writeObject(env);
			env = (Envelope)input.readObject();

			if (env.getMessage().compareTo("OK")==0) {
				System.out.printf("File %s deleted successfully\n", filename);
			} else {
				System.out.printf("Error deleting file %s (%s)\n", filename, env.getMessage());
				return false;
			}
		} catch (IOException e1) {
			e1.printStackTrace();
		} catch (ClassNotFoundException e1) {
			e1.printStackTrace();
		}

		return true;
	}

	public boolean download(String sourceFile, String destFile, UserToken token)
	{
		if (sourceFile.charAt(0)=='/') {
			sourceFile = sourceFile.substring(1);
		}

		File file = new File(destFile);
		try {
			if (!file.exists()) {
				file.createNewFile();
				FileOutputStream fos = new FileOutputStream(file);

				Envelope env = new Envelope("DOWNLOADF"); //Success
				env.addObject(sourceFile);
				env.addObject(token);
				output.writeObject(env);

				env = (Envelope)input.readObject();

				while (env.getMessage().compareTo("CHUNK")==0) {
					fos.write((byte[])env.getObjContents().get(0), 0, (Integer)env.getObjContents().get(1));
					System.out.printf(".");
					env = new Envelope("DOWNLOADF"); //Success
					output.writeObject(env);
					env = (Envelope)input.readObject();
				}
				fos.close();

				if(env.getMessage().compareTo("EOF")==0) {
					fos.close();
					System.out.printf("\nTransfer successful file %s\n", sourceFile);
					env = new Envelope("OK"); //Success
					output.writeObject(env);
				} else {
					System.out.printf("Error reading file %s (%s)\n", sourceFile, env.getMessage());
					file.delete();
					return false;
				}
			} else {
				System.out.printf("Error couldn't create file %s\n", destFile);
				return false;
			}
		} catch (IOException e1) {
			System.out.printf("Error couldn't create file %s\n", destFile);
			return false;
		} catch (ClassNotFoundException e1) {
			e1.printStackTrace();
			return false;
		}
		return true;
	}

	@SuppressWarnings("unchecked")
	public List<String> listFiles(UserToken token)
	{
		try {
			Envelope message = null, e = null;
			//Tell the server to return the member list
			message = new Envelope("LFILES");
			message.addObject(token); //Add requester's token
			output.writeObject(message);

			e = (Envelope)input.readObject();

			//If server indicates success, return the member list
			if(e.getMessage().equals("OK")) {
				return (List<String>)e.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
			}
		} catch(Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
		return null;
	}

	public boolean upload(String sourceFile, String destFile, String group, UserToken token)
	{
		if (!(new File(sourceFile).exists())) {
			System.out.printf("Source file %s does not exist\n", sourceFile);
			return false;
		}

		if (destFile.charAt(0)!='/') {
			destFile = "/" + destFile;
		}

		try {
			Envelope message = null, env = null;
			//Tell the server to return the member list
			message = new Envelope("UPLOADF");
			message.addObject(destFile);
			message.addObject(group);
			message.addObject(token); //Add requester's token
			output.writeObject(message);

			FileInputStream fis = new FileInputStream(sourceFile);
			env = (Envelope)input.readObject();

			//If server indicates success, return the member list
			if(env.getMessage().equals("READY")) {
				System.out.printf("Meta data upload successful\n");
			} else {
				System.out.printf("Upload failed: %s\n", env.getMessage());
				return false;
			}

			do {
				byte[] buf = new byte[4096];
				if (env.getMessage().compareTo("READY")!=0) {
					System.out.printf("Server error: %s\n", env.getMessage());
					return false;
				}
				message = new Envelope("CHUNK");
				int n = fis.read(buf); //can throw an IOException
				if (n > 0) {
					System.out.printf(".");
				} else if (n < 0) {
					System.out.println("Read error");
					return false;
				}

				message.addObject(buf);
				message.addObject(new Integer(n));
				output.writeObject(message);
				env = (Envelope)input.readObject();
			} while (fis.available()>0);

			//If server indicates success, return the member list
			if(env.getMessage().compareTo("READY")==0) {
				message = new Envelope("EOF");
				output.writeObject(message);
				env = (Envelope)input.readObject();
				if(env.getMessage().compareTo("OK")==0) {
					System.out.printf("\nFile data upload successful\n");
				} else {
					System.out.printf("\nUpload failed: %s\n", env.getMessage());
					return false;
				}

			} else {
				System.out.printf("Upload failed: %s\n", env.getMessage());
				return false;
			}
		} catch(Exception e1) {
			System.err.println("Error: " + e1.getMessage());
			e1.printStackTrace(System.err);
			return false;
		}
		return true;
	}

	public boolean condFileDelete (List<String> groupsDeleted, Token token)
	{
		List<String> files = listFiles(token);
		if (!groupsDeleted.isEmpty() && !files.isEmpty()) {
			System.out.println("Deleting group files:");
			for (String file : files) {
				System.out.println(file);
				delete(file, token);
			}
			return true;
		}
		return false;
	}
}

