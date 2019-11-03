/* Implements the GroupClient Interface */

import java.util.ArrayList;
import java.util.List;
import java.io.ObjectInputStream;
import java.security.PublicKey;
import javax.crypto.spec.SecretKeySpec;

public class GroupClient extends Client implements GroupClientInterface {

	public GroupClient()
	{
		crypto = new Crypto();
	}

	public boolean handshake()
	{
		try {
			Envelope message = null, response = null;
			// Receiving server's public key
			response = (Envelope) input.readObject();
			if (!response.getMessage().equals("PUBKEY") || response.getObjContents().size() != 1) {
				return false;
			}
			serverPublicKey = (PublicKey) response.getObjContents().get(0);
			// Sending client's public key
			message = new Envelope("PUBKEY");
			message.addObject(RSAKeys.getPublic());
			output.writeObject(message);
			// Receiving AES key
			response = (Envelope) input.readObject();
			if (!response.getMessage().equals("AESKEY") || response.getObjContents().size() != 1) {
				return false;
			}
			byte[] result = crypto.rsaDecrypt((byte [])response.getObjContents().get(0), RSAKeys.getPrivate());
			AESKey = new SecretKeySpec(result, "AES");
			//AESKey = crypto.rsaDecrypt((byte [])response.getObjContents().get(0), RSAKeys.getPrivate());
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
		return true;
	}

	public UserToken getToken(String username, String password)
	{
		try {
			UserToken token = null;
			Envelope message = null, response = null;

			//Tell the server to return a token.
			message = new Envelope("GET");
			message.addObject(username);
			message.addObject(password);
			send(message);

			//Get the response from the server
			response = receive();

			//Successful response
			if (response.getMessage().equals("OK")) {
				ArrayList<Object> temp = null;
				temp = response.getObjContents();

				if (temp.size() == 1) {
					token = (UserToken) temp.get(0);
					if (crypto.verify(serverPublicKey, token)) {
						return token;
					}
					System.err.println("Token signature verification failed");
				}
			}
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
		return null;
	}

	public boolean createUser(String username, String password, UserToken token)
	{
		try {
			Envelope message = null, response = null;
			//Tell the server to create a user
			message = new Envelope("CUSER");
			message.addObject(username); //Add user name string
			message.addObject(password);
			message.addObject(token); //Add the requester's token
			send(message);

			response = receive();

			//If server indicates success, return true
			if (response.getMessage().equals("OK")) {
				return true;
			}
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
		return false;
	}

	@SuppressWarnings("unchecked")
	public List<String> deleteUser(String username, UserToken token)
	{
		try {
			Envelope message = null, response = null;

			//Tell the server to delete a user
			message = new Envelope("DUSER");
			message.addObject(username); //Add user name
			message.addObject(token);  //Add requester's token
			send(message);

			response = receive();

			//If server indicates success, return true
			if (response.getMessage().equals("OK")) {
				return (List<String>) response.getObjContents().get(0);
			}
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
		return null;
	}

	public boolean createGroup(String groupname, UserToken token) {
		try {
			Envelope message = null, response = null;
			//Tell the server to create a group
			message = new Envelope("CGROUP");
			message.addObject(groupname); //Add the group name string
			message.addObject(token); //Add the requester's token
			send(message);

			response = receive();

			//If server indicates success, return true
			if (response.getMessage().equals("OK")) {
				return true;
			}
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
		return false;
	}

	@SuppressWarnings("unchecked")
	public List<String> deleteGroup(String groupname, UserToken token)
	{
		try {
			Envelope message = null, response = null;
			//Tell the server to delete a group
			message = new Envelope("DGROUP");
			message.addObject(groupname); //Add group name string
			message.addObject(token); //Add requester's token
			send(message);

			response = receive();
			//If server indicates success, return true
			if (response.getMessage().equals("OK")) {
				return (List<String>) response.getObjContents().get(0);
			}
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
		return null;
	}

	@SuppressWarnings("unchecked")
	public List<String> listMembers(String group, UserToken token)
	{
		try {
			Envelope message = null, response = null;
			//Tell the server to return the member list
			message = new Envelope("LMEMBERS");
			message.addObject(group); //Add group name string
			message.addObject(token); //Add requester's token
			send(message);

			response = receive();

			//If server indicates success, return the member list
			if (response.getMessage().equals("OK")) {
				return (List<String>) response.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
			}
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
		return null;
	}

	public boolean addUserToGroup(String username, String groupname, UserToken token)
	{
		try {
			Envelope message = null, response = null;
			//Tell the server to add a user to the group
			message = new Envelope("AUSERTOGROUP");
			message.addObject(username); //Add user name string
			message.addObject(groupname); //Add group name string
			message.addObject(token); //Add requester's token
			send(message);

			response = receive();
			//If server indicates success, return true
			if (response.getMessage().equals("OK")) {
				return true;
			}
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
		return false;
	}

	@SuppressWarnings("unchecked")
	public List<String> deleteUserFromGroup(String username, String groupname, UserToken token)
	{
		try {
			Envelope message = null, response = null;
			//Tell the server to remove a user from the group
			message = new Envelope("RUSERFROMGROUP");
			message.addObject(username); //Add user name string
			message.addObject(groupname); //Add group name string
			message.addObject(token); //Add requester's token
			send(message);

			response = receive();
			//If server indicates success, return true
			if (response.getMessage().equals("OK")) {
				return (List<String>)response.getObjContents().get(0);
			}
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
		return null;
	}
}
