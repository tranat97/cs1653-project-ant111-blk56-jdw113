/* File worker thread handles the business of uploading, downloading, and removing files for clients with valid tokens */

import java.lang.Thread;
import java.net.Socket;
import java.util.List;
import java.util.ArrayList;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.Key;
import java.util.Arrays;
import javax.crypto.spec.SecretKeySpec;

public class FileThread extends Thread
{
	private final Socket socket;
	private FileServer my_fs;
	private Key AESKey;
	private Crypto crypto;
	private ObjectInputStream input;
	private ObjectOutputStream output;
	
	public FileThread(Socket _socket, FileServer _fs)
	{
		socket = _socket;
		my_fs = _fs;
	}

	public void run()
	{
		boolean proceed = true;
		try {
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			input = new ObjectInputStream(socket.getInputStream());
			output = new ObjectOutputStream(socket.getOutputStream());
			crypto = new Crypto();
			Envelope response, e;
			
			if (!handshake()) {
				e = new Envelope("FAIL");
				output.writeObject(crypto.encrypt(e, AESKey));
				socket.close();
				proceed = false;
				System.out.println("Handshake failure; Disconnecting...");
			}

			while(proceed) {
				e = (Envelope)input.readObject();
				System.out.println("Request received: " + e.getMessage());

				// Handler to list files that this user is allowed to see
				if(e.getMessage().equals("LFILES")) {
					List<ShareFile> shareFiles = FileServer.fileList.getFiles();
					Token t = (Token)e.getObjContents().get(0);
					List<String> accessible = new ArrayList<String>();
					for (ShareFile f : shareFiles) {
						if (t.getGroups().contains(f.getGroup())) {
							accessible.add(f.getPath());
						}
					}
					response = new Envelope("OK");
					response.addObject(accessible);
					output.writeObject(response);
				} else if(e.getMessage().equals("UPLOADF")) {
					if(e.getObjContents().size() < 3) {
						response = new Envelope("FAIL-BADCONTENTS");
					} else {
						if(e.getObjContents().get(0) == null) {
							response = new Envelope("FAIL-BADPATH");
						}
						if(e.getObjContents().get(1) == null) {
							response = new Envelope("FAIL-BADGROUP");
						}
						if(e.getObjContents().get(2) == null) {
							response = new Envelope("FAIL-BADTOKEN");
						} else {
							String remotePath = (String)e.getObjContents().get(0);
							String group = (String)e.getObjContents().get(1);
							UserToken yourToken = (UserToken)e.getObjContents().get(2); //Extract token

							if (FileServer.fileList.checkFile(remotePath)) {
								System.out.printf("Error: file already exists at %s\n", remotePath);
								response = new Envelope("FAIL-FILEEXISTS"); //Success
							} else if (!yourToken.getGroups().contains(group)) {
								System.out.printf("Error: user missing valid token for group %s\n", group);
								response = new Envelope("FAIL-UNAUTHORIZED"); //Success
							} else  {
								File file = new File("shared_files/"+remotePath.replace('/', '_'));
								file.createNewFile();
								FileOutputStream fos = new FileOutputStream(file);
								System.out.printf("Successfully created file %s\n", remotePath.replace('/', '_'));

								response = new Envelope("READY"); //Success
								output.writeObject(response);

								e = (Envelope)input.readObject();
								while (e.getMessage().compareTo("CHUNK")==0) {
									fos.write((byte[])e.getObjContents().get(0), 0, (Integer)e.getObjContents().get(1));
									response = new Envelope("READY"); //Success
									output.writeObject(response);
									e = (Envelope)input.readObject();
								}

								if(e.getMessage().compareTo("EOF")==0) {
									System.out.printf("Transfer successful file %s\n", remotePath);
									FileServer.fileList.addFile(yourToken.getSubject(), group, remotePath);
									response = new Envelope("OK"); //Success
								} else {
									System.out.printf("Error reading file %s from client\n", remotePath);
									response = new Envelope("ERROR-TRANSFER"); //Success
								}
								fos.close();
							}
						}
					}
					output.writeObject(response);
				} else if (e.getMessage().compareTo("DOWNLOADF")==0) {
					String remotePath = (String)e.getObjContents().get(0);
					Token t = (Token)e.getObjContents().get(1);
					ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
					if (sf == null) {
						System.out.printf("Error: File %s doesn't exist\n", remotePath);
						e = new Envelope("ERROR_FILEMISSING");
						output.writeObject(e);

					} else if (!t.getGroups().contains(sf.getGroup())){
						System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
						e = new Envelope("ERROR_PERMISSION");
						output.writeObject(e);
					} else {
						try {
							File f = new File("shared_files/_"+remotePath.replace('/', '_'));
							if (!f.exists()) {
								System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
								e = new Envelope("ERROR_NOTONDISK");
								output.writeObject(e);
							} else {
								FileInputStream fis = new FileInputStream(f);

								do {
									byte[] buf = new byte[4096];
									if (e.getMessage().compareTo("DOWNLOADF")!=0) {
										System.out.printf("Server error: %s\n", e.getMessage());
										break;
									}
									e = new Envelope("CHUNK");
									int n = fis.read(buf); //can throw an IOException
									if (n > 0) {
										System.out.printf(".");
									} else if (n < 0) {
										System.out.println("Read error");
									}

									e.addObject(buf);
									e.addObject(new Integer(n));
									output.writeObject(e);

									e = (Envelope)input.readObject();
								} while (fis.available()>0);

								//If server indicates success, return the member list
								if(e.getMessage().compareTo("DOWNLOADF")==0) {
									e = new Envelope("EOF");
									output.writeObject(e);
									e = (Envelope)input.readObject();
									if(e.getMessage().compareTo("OK")==0) {
										System.out.printf("File data upload successful\n");
									} else {
										System.out.printf("Upload failed: %s\n", e.getMessage());
									}
								} else {
									System.out.printf("Upload failed: %s\n", e.getMessage());
								}
							}
						} catch(Exception e1) {
							System.err.println("Error: " + e.getMessage());
							e1.printStackTrace(System.err);

						}
					}
				} else if (e.getMessage().compareTo("DELETEF")==0) {
					String remotePath = (String)e.getObjContents().get(0);
					Token t = (Token)e.getObjContents().get(1);
					ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
					if (sf == null) {
						System.out.printf("Error: File %s doesn't exist\n", remotePath);
						e = new Envelope("ERROR_DOESNTEXIST");
					} else if (!t.getGroups().contains(sf.getGroup())) {
						System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
						e = new Envelope("ERROR_PERMISSION");
					} else {
						try {
							File f = new File("shared_files/"+"_"+remotePath.replace('/', '_'));

							if (!f.exists()) {
								System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
								e = new Envelope("ERROR_FILEMISSING");
							} else if (f.delete()) {
								System.out.printf("File %s deleted from disk\n", "_"+remotePath.replace('/', '_'));
								FileServer.fileList.removeFile("/"+remotePath);
								e = new Envelope("OK");
							} else {
								System.out.printf("Error deleting file %s from disk\n", "_"+remotePath.replace('/', '_'));
								e = new Envelope("ERROR_DELETE");
							}
						} catch(Exception e1) {
							System.err.println("Error: " + e1.getMessage());
							e1.printStackTrace(System.err);
							e = new Envelope(e1.getMessage());
						}
					}
					output.writeObject(e);
				}
				else if(e.getMessage().equals("DISCONNECT")) {
					socket.close();
					proceed = false;
				}
			}
		} catch(Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
	
	private boolean handshake() 
	{
		Envelope response, e;
		byte[] r1, r2, keyBytes;
		try{
			//HANDSHAKE: send public key
			response = new Envelope("PUBKEY");
			response.addObject(my_fs.RSAKeys.getPublic());
			output.writeObject(response);
			//Challenge 1
			e = (Envelope)input.readObject();
			if(!e.getMessage().equals("R1") || e.getObjContents().size()!=2) {
				throw new Exception("Challenge 1 Failure");
			}
			System.out.println("Request received: " + e.getMessage());
			//Decrypt message
			r1 = crypto.rsaDecrypt((byte[])e.getObjContents().get(0), my_fs.RSAKeys.getPrivate());
			keyBytes = crypto.rsaDecrypt((byte[])e.getObjContents().get(1), my_fs.RSAKeys.getPrivate());
			AESKey = new SecretKeySpec(keyBytes, "AES");
			//System.out.println("R1 = "+ (new String(crypto.rsaDecrypt(r1, my_fs.RSAKeys.getPrivate()))));
			//Generate new nonce
			r2 = crypto.generateRandomBytes(32);
			//System.out.println("R2 = "+(new String(r2)));
			//Challenge 1 Response
			response = new Envelope("R2");
			response.addObject(r1);
			response.addObject(r2);
			output.writeObject(crypto.encrypt(response, AESKey));
			//Validate Challenge 2
			e = crypto.decrypt((Envelope)input.readObject(), AESKey);
			r1 = (byte[])e.getObjContents().get(0);
			if(!e.getMessage().equals("R2_RESPONSE") || e.getObjContents().size()!=1 || !Arrays.equals(r1, r2)) {
				throw new Exception("Challenge 2 Failure");
			}
            System.out.println("Request received: " + e.getMessage());
			//Return an OK message
			e = new Envelope("OK");
			output.writeObject(crypto.encrypt(e, AESKey));
            System.out.println("Handshake Successful; Connected to Host on "+socket.getInetAddress()+"...");
			return true;
		} catch (Exception ex){
			System.err.println("Error: " + ex.getMessage());
			ex.printStackTrace(System.err);
			return false;
		}
	}
}
