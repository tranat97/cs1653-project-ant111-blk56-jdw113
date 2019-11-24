import java.net.Socket;
import java.net.UnknownHostException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PublicKey;
import java.security.Key;
import java.io.*;
import java.util.*;

public abstract class Client {

	/* protected keyword is like private but subclasses have access
	 * Socket and input/output streams
	 */
	protected Socket sock;
	protected ObjectOutputStream output;
	protected ObjectInputStream input;
	protected PublicKey serverPublicKey;
	protected Key AESKey;
	protected Crypto crypto;
    protected Hashtable<String, String> knownKeys;
    protected File keyFile;

	protected boolean handshake(String server)
	{
		String ans = null;
		Envelope message = null, response = null;
		Scanner in = new Scanner(System.in);
		byte[] r1 = null, r2 = null;
        boolean keySaved = false;
		try {			
			response = (Envelope) input.readObject();
			if (!response.getMessage().equals("PUBKEY") || response.getObjContents().size() != 1) {
				return false;
			}
			//extract public key, hash it and display
			serverPublicKey = (PublicKey) response.getObjContents().get(0);
            String keyHash = crypto.bytesToHex(crypto.hash(serverPublicKey.getEncoded()));
            //checking if there is a saved key associated with the IP
            if(knownKeys.containsKey(sock.getInetAddress().toString())) {
                //if keys match
                if(knownKeys.get(sock.getInetAddress().toString()).equals(keyHash)) {
                    keySaved = true;
                }
            }
            if (!keySaved) {
                System.out.println(server + " Public Key: " + crypto.bytesToHex(crypto.hash(serverPublicKey.getEncoded())));
                do {
                    System.out.print("Do you trust this key? (y/n): ");
                    ans = in.next();
                    if (ans.toLowerCase().equals("n")) {
                        return false;
                    }
                } while (!ans.toLowerCase().equals("y"));
            }
			
			//CHALLENGE START-----------------
			//generate values
			AESKey = crypto.generateAESKey();
			r1 = crypto.generateRandomBytes(32);
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
			message = new Envelope("R2_RESPONSE");
			message.addObject(r2);
			output.writeObject(crypto.encrypt(message, AESKey));
			//Recieve OK message
			response = crypto.decrypt((Envelope)input.readObject(), AESKey);
			if (!response.getMessage().equals("OK") || response.getObjContents().size()!=0) {
				throw new Exception("Challenge 2 failure");
			}
			//CHALLENGE END----------------
            if (!keySaved) {
                saveServerKey();
            }
			return true;
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}
    
    protected void getServerKeys()
	{
        String ip, keyHash; 
        try {
            keyFile.createNewFile();
            BufferedReader savedKeys = new BufferedReader(new FileReader(keyFile));
            while (savedKeys.ready()) {
                ip = savedKeys.readLine();
                keyHash = savedKeys.readLine();
                knownKeys.put(ip, keyHash);
            }
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
	}
    
    protected boolean saveServerKey()
    {
        FileWriter fw;
        String ip = sock.getInetAddress().toString();
        String keyHash = crypto.bytesToHex(crypto.hash(serverPublicKey.getEncoded()));
        String entry = ip+"\n"+keyHash+"\n";
        try {
            //System.out.println(entry);
            fw = new FileWriter(keyFile, true);
            fw.write(entry);
            fw.close();
        } catch(Exception e) {
            System.err.println(e.getMessage());
            return false;
        }
        return true;
    }

	public boolean connect(final String server, final int port) {
		System.out.println("attempting to connect");
		try {
			sock = new Socket(server, port);
			output = new ObjectOutputStream(sock.getOutputStream());
			input = new ObjectInputStream(sock.getInputStream());
			System.out.println("successfully connected to host " + server);
			return true;
		} catch (UnknownHostException e) {
			System.out.println("ERROR: could not connect to the host " + server);
			e.printStackTrace();
		} catch (IOException e) {
			System.out.println("ERROR: IO error occured while setting up connecting to host " + server);
			e.printStackTrace();
		}
		return false;
	}

	public boolean isConnected() {
		if (sock == null || !sock.isConnected()) {
			return false;
		}
		else {
			return true;
		}
	}

	public void disconnect() {
		if (isConnected()) {
			try {
				Envelope message = new Envelope("DISCONNECT");
				send(message);
			} catch(Exception e) {
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
			}
		}
	}


	protected Envelope receive() throws Exception
	{
		return crypto.decrypt((Envelope) input.readObject(), AESKey);
	}

	protected void send(Envelope e) throws Exception
	{
		output.writeObject(crypto.encrypt(e, AESKey));
	}

    
}
