/* Implements the GroupClient Interface */

import java.util.ArrayList;
import java.util.List;
import java.io.ObjectInputStream;
import java.security.PublicKey;
import java.security.KeyPair;
import java.security.Key;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.util.*;

public class GroupClient extends Client implements GroupClientInterface {

	private KeyPair RSAKeys;

	public GroupClient()
	{
		crypto = new Crypto();
        knownKeys = new Hashtable<String, String>();
        keyFile = new File("GroupServerKnownKeys.txt");
        getServerKeys();
		messageNumber = 0;
	}

	public boolean handshake()
	{
		return handshake("Group Server");
	}

	private boolean getRSAKeys(String publicPath, String privatePath)
	{
		RSAKeys = crypto.getRSAKeys(publicPath, privatePath);
		return RSAKeys != null;
	}

	public UserToken getToken(String username, String password, PublicKey pubKey)
	{
		try {
			UserToken token = null;
			Envelope message = null, response = null;

			//Tell the server to return a token.
			message = new Envelope("GET");
			message.addObject(username);
			message.addObject(password);
			message.addObject(crypto.fingerprint(pubKey)); //Send fingerprint of the public key
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

	public boolean changePassword(String password, UserToken token)
	{
		try {
			Envelope message = null, response = null;

			//Tell the server to change password
			message = new Envelope("CPASSWORD");
			message.addObject(token);
			message.addObject(password);
			send(message);

			//Get the response from the server
			response = receive();

			if (response.getMessage().equals("OK")) {
				return true;
			} 
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
		return false;
	}

	public boolean createUser(String username, String password, UserToken token)
	{
		try {
			Envelope message = null, response = null;
			//Tell the server to create a user
			message = new Envelope("CUSER");
			message.addObject(token); //Add the requester's token
			message.addObject(username); //Add user name string
			message.addObject(password);
			send(message);

			response = receive();

			//If server indicates success, return true
			if (response.getMessage().equals("OK")) {
				return true;
			} else if (response.getMessage().equals("INVALID_USERNAME")) {
				System.out.println(username + " contains an invalid character");
			}
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
		return false;
	}

	@SuppressWarnings("unchecked")
	public UserToken deleteUser(String username, UserToken token, PublicKey pubKeyFS)
	{
		try {
			Envelope message = null, response = null;

			//Tell the server to delete a user
			message = new Envelope("DUSER");
			message.addObject(token);  //Add requester's token
			message.addObject(username); //Add user name
			message.addObject(crypto.fingerprint(pubKeyFS)); //Add FS public key
			send(message);

			response = receive();

			//If server indicates success, return true
			if (response.getMessage().equals("OK")) {
				return (UserToken) response.getObjContents().get(0);
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
			message.addObject(token); //Add the requester's token
			message.addObject(groupname); //Add the group name string
			send(message);

			response = receive();

			//If server indicates success, return true
			if (response.getMessage().equals("OK")) {
				return true;
			} else if (response.getMessage().equals("INVALID_GROUPNAME")) {
				System.out.println(groupname + " contains an invalid character");
			}
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
		return false;
	}

	@SuppressWarnings("unchecked")
	public UserToken deleteGroup(String groupname, UserToken token, PublicKey pubKeyFS)
	{
		try {
			Envelope message = null, response = null;
			//Tell the server to delete a group
			message = new Envelope("DGROUP");
			message.addObject(token); //Add requester's token
			message.addObject(groupname); //Add group name string
			message.addObject(crypto.fingerprint(pubKeyFS)); //Add FS public key fingerprint
			send(message);

			response = receive();
			//If server indicates success, return true
			if (response.getMessage().equals("OK")) {
				return (UserToken) response.getObjContents().get(0);
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
			message.addObject(token); //Add requester's token
			message.addObject(group); //Add group name string
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
			message.addObject(token); //Add requester's token
			message.addObject(username); //Add user name string
			message.addObject(groupname); //Add group name string
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
	public UserToken deleteUserFromGroup(String username, String groupname, UserToken token, PublicKey pubKeyFS)
	{
		try {
			Envelope message = null, response = null;
			//Tell the server to remove a user from the group
			message = new Envelope("RUSERFROMGROUP");
			message.addObject(token); //Add requester's token
			message.addObject(username); //Add user name string
			message.addObject(groupname); //Add group name string
			message.addObject(crypto.fingerprint(pubKeyFS)); //Add fs fingerprint
			send(message);

			response = receive();
			//If server indicates success, return true
			if (response.getMessage().equals("OK")) {
				return (UserToken)response.getObjContents().get(0);
			}
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
		return null; 
	}
	
	public KeyInfo keyRequest(String groupname, Integer keyNum, UserToken token)
	{
		KeyInfo reqKey = null;
		Envelope message = null, response = null;
		//request Key from group server
		try {
			message = new Envelope("KEYREQ");
			message.addObject(token);
			message.addObject(groupname);
			message.addObject(keyNum);
			send(message);
			//Read response
			response = receive();
			if(response.getMessage().compareTo("KEY")==0) {
				if(response.getObjContents().get(0)!=null && response.getObjContents().get(1)!=null) {
					reqKey = new KeyInfo((Key)response.getObjContents().get(0), (Integer)response.getObjContents().get(1));
                    
				} else {
					System.out.println("Key not found");
				}
			} else {
				System.out.println("Format Error");
			}
			
		} catch(Exception el) {
			System.out.println("Error sending/receiving request");
			return null;
		}
		return reqKey;
	}
}
