import java.net.Socket;
import java.net.UnknownHostException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PublicKey;
import java.security.Key;

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
