/* FileClient provides all the client functionality regarding the file server */
import java.io.*;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.*;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.spec.*;
import java.security.Key;

public class FileClient extends Client implements FileClientInterface
{
	public FileClient()
	{
		crypto = new Crypto();
        knownKeys = new Hashtable<String, String>();
        keyFile = new File("FileServerKnownKeys.txt");
        getServerKeys();
	}

	public boolean handshake()
	{
		return handshake("File Server");
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
		env.addObject(token);
		env.addObject(remotePath);
		try {
			send(env);
			env = receive();

			if (env.getMessage().compareTo("OK")==0) {
				System.out.printf("File %s deleted successfully\n", filename);
			} else {
				System.out.printf("Error deleting file %s (%s)\n", filename, env.getMessage());
				return false;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		return true;
	}

	public boolean download(String sourceFile, String destFile, UserToken token, Key key)
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
				env.addObject(token);
				env.addObject(sourceFile);
				send(env);
                        
				env = receive();
                byte[] iv = null;
				if (env.getMessage().compareTo("IV")==0) {
					iv = (byte[])env.getObjContents().get(0);
                    //System.out.println("download IV = "+Arrays.toString(iv));
					env = new Envelope("READY");
					send(env);
				} else {
					return false;
				}
				
				env = receive();

				while (env.getMessage().compareTo("CHUNK")==0) {
                    byte[] block = (byte[])env.getObjContents().get(0);
                    //int n = (Integer)env.getObjContents().get(1);
                    //System.out.println("\nbefore "+Arrays.toString(block));
                    block = crypto.decrypt(block, iv, key);
                    int n=0;
                    for (byte b: block) {
                        if (b == 0)
                            break;
                        n++;
                    }
                    //System.out.println("after "+Arrays.toString(block));
					fos.write(block, 0, n);
					System.out.printf(".");
					env = new Envelope("READY"); //Success
					send(env);
					env = receive();
				}
				fos.close();

				if(env.getMessage().compareTo("EOF")==0) {
					fos.close();
					System.out.printf("\nTransfer successful file %s\n", sourceFile);
					env = new Envelope("OK"); //Success
					send(env);
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
		} catch (Exception e1) {
			//e1.printStackTrace();
            System.out.printf("Error: download/decryption failed\n");
			return false;
		}
		return true;
	}
	
	public Integer keyRequest(String sourceFile, UserToken token)
	{
		Integer keyNum = null;
		Envelope env = null;
		try {
			env = new Envelope("KEYREQ");
			env.addObject(token);
			env.addObject(sourceFile);
			send(env);
			//Read response
			env = receive();
			if(env.getMessage().compareTo("KEYNUM")==0) {
				if(env.getObjContents().get(0)!=null) {
					keyNum = (Integer)env.getObjContents().get(0);
				} else {
					System.out.println("Key number not found");
				}
			} else {
				System.out.println("ERROR: The file does not exist or you do not have access to the file: "+sourceFile);
			}
			
		} catch(Exception el) {
			System.out.println("Error sending/receiving request");
			return null;
		}
		
		return keyNum;
	}

	@SuppressWarnings("unchecked")
	public List<String> listFiles(UserToken token)
	{
		try {
			Envelope message = null, e = null;
			//Tell the server to return the member list
			message = new Envelope("LFILES");
			message.addObject(token); //Add requester's token
			send(message);

			e = receive();

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

	public boolean upload(String sourceFile, String destFile, String group, UserToken token, Key key, Integer keyNum)
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
			byte[] iv = crypto.generateRandomBytes(16);
            //System.out.println("upload IV = "+Arrays.toString(iv));
			//Tell the server to return the member list
			message = new Envelope("UPLOADF");
			message.addObject(token); //Add requester's token
			message.addObject(destFile);
			message.addObject(group);
			message.addObject(keyNum);
			message.addObject(iv);
			send(message);

			FileInputStream fis = new FileInputStream(sourceFile);
			env = receive();

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
                //System.out.println("before "+Arrays.toString(buf));
                buf = crypto.encrypt(buf, iv, key);
                //System.out.println("\nafter "+Arrays.toString(buf));
				message.addObject(buf);
				message.addObject(new Integer(buf.length));
				send(message);
				env = receive();
			} while (fis.available()>0);

			//If server indicates success, return the member list
			if(env.getMessage().compareTo("READY")==0) {
				message = new Envelope("EOF");
				message.addObject(iv);
				send(message);
				env = receive();
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

	public boolean condFileDelete(UserToken token)
	{
		List<String> files = listFiles(token);
		if (!token.getGroups().isEmpty() && !files.isEmpty()) {
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

