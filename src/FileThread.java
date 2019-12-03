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
import java.io.IOException;
import java.security.Key;
import java.security.PublicKey;
import java.util.Arrays;
import javax.crypto.spec.SecretKeySpec;

public class FileThread extends Thread
{
	private final Socket socket;
	private FileServer my_fs;
	private Key AESKey;
	private Key HMACKey;
	private Crypto crypto;
	private ObjectInputStream input;
	private ObjectOutputStream output;
	private int messageNumber;
	
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
				send(e);
				socket.close();
				proceed = false;
				System.out.println("Handshake failure; Disconnecting...");
			}
			/* After this point, all envelope sending and receiving will
			*  be done through send and recieve methods. These methods
			*  encrypt and decrypt envelopes before sending.
			*/
			while(proceed) {
				e = receive();
				System.out.println("Request received: " + e.getMessage());
				if (!checkToken(e)) {
					System.out.println("Forged or modified token attempt");
					response = new Envelope("BAD-TOKEN");
					send(response);
				} else if(e.getMessage().equals("LFILES")) {
					// Handler to list files that this user is allowed to see
					List<ShareFile> shareFiles = FileServer.fileList.getFiles();
					UserToken t = (UserToken)e.getObjContents().get(0);
					List<String> accessible = new ArrayList<String>();
					for (ShareFile f : shareFiles) {
						if (t.getGroups().contains(f.getGroup())) {
							accessible.add(f.getPath());
						}
					}
					response = new Envelope("OK");
					response.addObject(accessible);
					send(response);
				} else if(e.getMessage().equals("UPLOADF")) {
					if(e.getObjContents().size() < 5) {
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
						} 
						if(e.getObjContents().get(3) == null) {
							response = new Envelope("FAIL-BADKEY");
						}
						if(e.getObjContents().get(4) == null) {
							response = new Envelope("FAIL-IV");
						} else {
							UserToken yourToken = (UserToken)e.getObjContents().get(0); //Extract token
							String remotePath = (String)e.getObjContents().get(1);
							String group = (String)e.getObjContents().get(2);
							Integer key = (Integer)e.getObjContents().get(3);
							byte[] iv = (byte[])e.getObjContents().get(4);
                            //System.out.println("upload IV = "+Arrays.toString(iv));

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
								send(response);

								e = receive();
								while (e.getMessage().compareTo("CHUNK")==0) {
									fos.write((byte[])e.getObjContents().get(0), 0, (Integer)e.getObjContents().get(1));
									response = new Envelope("READY"); //Success
									send(response);
									e = receive();
								}

								if(e.getMessage().compareTo("EOF")==0) {
									System.out.printf("Transfer successful file %s\n", remotePath);
									FileServer.fileList.addFile(yourToken.getSubject(), group, remotePath, key, iv);
									response = new Envelope("OK"); //Success
								} else {
									System.out.printf("Error reading file %s from client\n", remotePath);
									response = new Envelope("ERROR-TRANSFER"); //Success
								}
								fos.close();
							}
						}
					}
					send(response);
				} else if (e.getMessage().compareTo("DOWNLOADF")==0) {
					UserToken t = (UserToken)e.getObjContents().get(0);
					String remotePath = (String)e.getObjContents().get(1);
					ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
					if (sf == null) {
						System.out.printf("Error: File %s doesn't exist\n", remotePath);
						e = new Envelope("ERROR_FILEMISSING");
						send(e);
					} else if (!t.getGroups().contains(sf.getGroup())){
						System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
						e = new Envelope("ERROR_PERMISSION");
						send(e);
					} else {
						try {
							File f = new File("shared_files/_"+remotePath.replace('/', '_'));
							if (!f.exists()) {
								System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
								e = new Envelope("ERROR_NOTONDISK");
								send(e);
							} else {
								FileInputStream fis = new FileInputStream(f);
								//Send User the IV they need to decrypt
								e = new Envelope("IV");
                                //System.out.println("download IV = "+Arrays.toString(sf.getIV()));
								e.addObject(sf.getIV());
								send(e);
								
								e = receive();
								if(e.getMessage().compareTo("READY")==0) {
									do {
										byte[] buf = new byte[4112];
										if (e.getMessage().compareTo("READY")!=0) {
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
										send(e);

										e = receive();
									} while (fis.available()>0);

									//Send EOF
									if(e.getMessage().compareTo("READY")==0) {
										e = new Envelope("EOF");
										//e.addObject(sf.getIV());
										send(e);
										e = receive();
										if(e.getMessage().compareTo("OK")==0) {
											System.out.printf("\nFile data upload successful\n");
										} else {
											System.out.printf("Upload failed: %s\n", e.getMessage());
										}
									} else {
										System.out.printf("Upload failed: %s\n", e.getMessage());
									}
								} else {
									System.out.printf("Upload failed: %s\n", e.getMessage());
								}
							}
						} catch(IOException e1) {
							System.err.println("Error: " + e.getMessage());
							e1.printStackTrace(System.err);
						}
					}
				} else if (e.getMessage().compareTo("DELETEF")==0) {
					UserToken t = (UserToken)e.getObjContents().get(0);
					String remotePath = (String)e.getObjContents().get(1);
					ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
					if (sf == null) {
						System.out.printf("Error: File %s doesn't exist\n", remotePath);
						e = new Envelope("ERROR_DOESNTEXIST");
					} else if (!t.getGroups().contains(sf.getGroup())) {
						System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
						e = new Envelope("ERROR_PERMISSION");
					} else {
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
					}
					send(e);
				} else if (e.getMessage().equals("KEYREQ"))  {
					UserToken t = (UserToken)e.getObjContents().get(0);
					String remotePath = (String)e.getObjContents().get(1);
					ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
					if (sf == null) {
						System.out.printf("Error: File %s doesn't exist\n", remotePath);
						e = new Envelope("ERROR_FILEMISSING");
						send(e);
					} else if (!t.getGroups().contains(sf.getGroup())){
						System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
						e = new Envelope("ERROR_PERMISSION");
						send(e);
					} else {
						try {
							File f = new File("shared_files/_"+remotePath.replace('/', '_'));
							if (!f.exists()) {
								System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
								e = new Envelope("ERROR_NOTONDISK");
								send(e);
							} else {
								e = new Envelope("KEYNUM");
								e.addObject(sf.getKey());
								send(e);
							}
						} catch(IOException e1) {
							System.err.println("Error: " + e.getMessage());
							e1.printStackTrace(System.err);
						}
					}
				} else if(e.getMessage().equals("DISCONNECT")) {
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
			if(!e.getMessage().equals("R1") || e.getObjContents().size()!=3) {
				throw new Exception("Challenge 1 Failure");
			}
			System.out.println("Request received: " + e.getMessage());
			//Decrypt message
			r1 = crypto.rsaDecrypt((byte[])e.getObjContents().get(0), my_fs.RSAKeys.getPrivate());
			keyBytes = crypto.rsaDecrypt((byte[])e.getObjContents().get(1), my_fs.RSAKeys.getPrivate());
			AESKey = new SecretKeySpec(keyBytes, "AES");
			keyBytes = crypto.rsaDecrypt((byte[])e.getObjContents().get(2), my_fs.RSAKeys.getPrivate());
			HMACKey = new SecretKeySpec(keyBytes, "AES");
			//System.out.println("R1 = "+ (new String(crypto.rsaDecrypt(r1, my_fs.RSAKeys.getPrivate()))));
			//Generate new nonce
			r2 = crypto.generateRandomBytes(32);
			//System.out.println("R2 = "+(new String(r2)));
			//Challenge 1 Response
			response = new Envelope("R2");
			response.addObject(r1);
			response.addObject(r2);
			send(response);
			//Validate Challenge 2
			e = receive();
			r1 = (byte[])e.getObjContents().get(0);
			if(!e.getMessage().equals("R2_RESPONSE") || e.getObjContents().size()!=1 || !Arrays.equals(r1, r2)) {
				throw new Exception("Challenge 2 Failure");
			}
            System.out.println("Request received: " + e.getMessage());
			//Return an OK message
			e = new Envelope("OK");
			send(e);
            System.out.println("Handshake Successful; Connected to Host on "+socket.getInetAddress()+"...");
			return true;
		} catch (Exception ex){
			System.err.println("Error: " + ex.getMessage());
			ex.printStackTrace(System.err);
			return false;
		}
	}

	private boolean checkToken(Envelope e)
	{
		final String message = e.getMessage();
		if (message.equals("UPLOADF")   || message.equals("LFILES") ||
			message.equals("DOWNLOADF") || message.equals("DELETEF") ||
            message.equals("KEYREQ")){
			// token is the first object in all of these messages
			if (e.getObjContents().size() == 0) {
				return false;
			}
			UserToken t = (UserToken) e.getObjContents().get(0);
			return t != null && crypto.verify(my_fs.trustedGroupServer, t) && checkFingerprint(t) && checkTimestamp(t);
		}
		// no token in message, so token is valid
		return true;
	}

	private Envelope receive() throws Exception
	{
		Envelope e = crypto.decrypt((Envelope) input.readObject(), messageNumber++, AESKey, HMACKey);
		if (e == null) {
			send(new Envelope("FAIL"));
			socket.close();
			throw new Exception("Failed to verify HMAC");
		}
		return e;
	}

	private void send(Envelope e) throws Exception
	{
		output.writeObject(crypto.encrypt(e, messageNumber++, AESKey, HMACKey));
	}

	private boolean checkFingerprint(UserToken myToken)
	{
		PublicKey fsPubKey = my_fs.RSAKeys.getPublic();
		String fsFingerprint = crypto.fingerprint(fsPubKey);
		if(fsFingerprint.equals(myToken.getTarget())) {
			return true;
		} else {
			return false;
		}

	}
	private boolean checkTimestamp(UserToken myToken)
	{
		long unixTime = System.currentTimeMillis();
		long tokenTimestamp = myToken.getTimestamp();
		if(unixTime - tokenTimestamp <= 3600000) {       //check to see if timestamp older than 1 hour
			return true;
		} else {
			return false;
		}

	}
}
