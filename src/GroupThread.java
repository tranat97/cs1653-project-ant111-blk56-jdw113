/* This thread does all the work. It communicates with the client through Envelopes.
 *
 */
import java.lang.Thread;
import java.net.Socket;
import java.io.*;
import java.util.*;
import java.security.Key;

public class GroupThread extends Thread {

    private final Socket socket;
    private GroupServer my_gs;
	private Key clientPublicKey;
	private Key AESKey;

    public GroupThread(Socket _socket, GroupServer _gs) {
        socket = _socket;
        my_gs = _gs;
    }

    public void run() {
        boolean proceed = true;

        try {
            //Announces connection and opens object streams
            System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
            final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
            final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
            Envelope message, response;

			// handshake
			// sending our public key
			response = new Envelope("PUBKEY");
			response.addObject(my_gs.RSAKeys.getPublic());
			output.writeObject(response);
			// recieving their public key
			message = (Envelope) input.readObject();
			if (!message.getMessage().equals("PUBKEY") || message.getObjContents().size() != 1)
			{
				response = new Envelope("FAIL");
				response.addObject(null);
				output.writeObject(response);
				return;
			}
			clientPublicKey = (Key) message.getObjContents().get(0);
			// generating and sending AES key
			AESKey = my_gs.crypto.generateAESKey();
			response = new Envelope("AESKEY");
			response.addObject(my_gs.crypto.encryptAESKey(AESKey, clientPublicKey));
			output.writeObject(response);
            do {
                message = (Envelope) input.readObject();
                System.out.println("Request received: " + message.getMessage());

                if (message.getMessage().equals("GET"))//Client wants a token
                {
					if (message.getObjContents().size() != 2)
					{
						response = new Envelope("FAIL");
						response.addObject(null);
						output.writeObject(response);
					}
					else
					{
						byte[] IV = (byte []) message.getObjContents().get(0);
						byte[] encryptedCredentials= (byte []) message.getObjContents().get(1); 
						if (IV == null || encryptedCredentials == null) {
							response = new Envelope("FAIL");
							response.addObject(null);
							output.writeObject(response);
						} else {
							String credentials[] = new String(my_gs.crypto.decrypt(encryptedCredentials, IV, AESKey)).split(":", 2);
							if (my_gs.userList.checkPassword(credentials[0], credentials[1])) {
								UserToken yourToken = createToken("admin"); //Create a token
								byte[] hash = my_gs.crypto.hash(yourToken.toString());
								IV = my_gs.crypto.generateIV();

								//Respond to the client. On error, the client will receive a null token
								response = new Envelope("OK");
								response.addObject(IV);
								response.addObject(my_gs.crypto.encrypt(yourToken.toBytes(), IV, AESKey));
								//IV[0]++;
								// I would like to modify the IV by a constant here,
								// but it changes the IV previously added to response
								// we need to copy it and then increment it
								response.addObject(my_gs.crypto.encrypt(my_gs.crypto.sign(my_gs.RSAKeys.getPrivate(), yourToken.toString().getBytes()), IV, AESKey));
								output.writeObject(response);
							} else {
								response = new Envelope("FAIL");
								response.addObject(null);
								output.writeObject(response);
							}
						}
					}
                } else if (message.getMessage().equals("CUSER")) //Client wants to create a user
                {
                    if (message.getObjContents().size() < 2) {
                        response = new Envelope("FAIL");
                    } else {
                        response = new Envelope("FAIL");

                        if (message.getObjContents().get(0) != null && message.getObjContents().get(1) != null) {
                            String username = (String) message.getObjContents().get(0); //Extract the username
							String password = (String) message.getObjContents().get(1);
                            UserToken yourToken = (UserToken) message.getObjContents().get(2); //Extract the token

                            if (createUser(username, password, yourToken)) {
                                response = new Envelope("OK"); //Success
                            }
                        }
                    }

                    output.writeObject(response);
                } else if (message.getMessage().equals("DUSER")) //Client wants to delete a user
                {

                    if (message.getObjContents().size() < 2) {
                        response = new Envelope("FAIL");
                    } else {
                        response = new Envelope("FAIL");

                        if (message.getObjContents().get(0) != null && message.getObjContents().get(1) != null) {
                            String username = (String) message.getObjContents().get(0); //Extract the username
                            UserToken yourToken = (UserToken) message.getObjContents().get(1); //Extract the token
                            List<String> groupsDeleted = deleteUser(username, yourToken);
                            if (groupsDeleted != null) {
                                response = new Envelope("OK"); //Success
                                response.addObject(groupsDeleted);
                            }
                        }
                    }

                    output.writeObject(response);
                } else if (message.getMessage().equals("CGROUP")) //Client wants to create a group
                {
                    //check if envelope has correct amount of information
                    if (message.getObjContents().size() < 2) {
                        response = new Envelope("FAIL");
                    } else {
                        response = new Envelope("FAIL");
                        if (message.getObjContents().get(0) != null && message.getObjContents().get(1) != null) {
                            UserToken yourToken = (UserToken) message.getObjContents().get(1); //Extract the token
                            String groupname = (String) message.getObjContents().get(0); //Extract the groupname from message
                            String username = yourToken.getSubject(); //extract username from the token
                            ArrayList<String> checkMembers = new ArrayList<String>();
                            checkMembers = my_gs.userList.getMembers(groupname);
                            if(checkMembers.isEmpty())
                            {
                                my_gs.userList.addGroup(username, groupname); //add user to group
                                my_gs.userList.addOwnership(username, groupname); //give creator ownership of the group
                                response = new Envelope("OK"); //Success
                            }
                        }
                    }
                    output.writeObject(response);
                } else if (message.getMessage().equals("DGROUP")) //Client wants to delete a group
                {
                    //check if envelope has correct amount of information
                    if (message.getObjContents().size() < 2) {
                        response = new Envelope("FAIL");
                    } else {
                        response = new Envelope("FAIL");

                        if (message.getObjContents().get(0) != null && message.getObjContents().get(1) != null) {
                            UserToken yourToken = (UserToken) message.getObjContents().get(1); //Extract the token
                            String username = yourToken.getSubject(); //extract username from the token
                            String groupname = (String) message.getObjContents().get(0); //Extract the groupname from message
                            if (my_gs.userList.getUserOwnership(username).contains(groupname)) //check if the user has ownership of the group they are attempting to delete
                            {
                                my_gs.userList.removeOwnership(username, groupname); //remove ownership from the creator
                                deleteGroup(groupname, (Token) yourToken);
                                response = new Envelope("OK"); //Success
                                ArrayList<String> groupsDeleted = new ArrayList<String>();
                                groupsDeleted.add(groupname);
                                response.addObject((List<String>) groupsDeleted);
                            }
                        }
                    }
                    output.writeObject(response);
                } else if (message.getMessage().equals("LMEMBERS")) //Client wants a list of members in a group
                {
                    //check if envelope has correct amount of information
                    if (message.getObjContents().size() < 2) {
                        response = new Envelope("FAIL");
                    } else {
                        response = new Envelope("FAIL");

                        if (message.getObjContents().get(0) != null && message.getObjContents().get(1) != null) {
                            UserToken yourToken = (UserToken) message.getObjContents().get(1); //Extract the token
                            String username = yourToken.getSubject(); //extract username from the token
                            String groupname = (String) message.getObjContents().get(0); //Extract the groupname from message
                            if (my_gs.userList.getUserOwnership(username).contains(groupname)) //check if the user has ownership of the group they are attempting to list members of
                            {
                                ArrayList<String> memberList = my_gs.userList.getMembers(groupname);
                                response = new Envelope("OK");
                                response.addObject(memberList);
                            }
                        }
                    }
                    output.writeObject(response);
                } else if (message.getMessage().equals("AUSERTOGROUP")) //Client wants to add user to a group
                {
                    if (message.getObjContents().size() < 3) {
                        response = new Envelope("FAIL");
                    } else {
                        response = new Envelope("FAIL");

                        if (message.getObjContents().get(0) != null && message.getObjContents().get(1) != null && message.getObjContents().get(2) != null) {
                            UserToken yourToken = (UserToken) message.getObjContents().get(2); //Extract the token
                            String owner = yourToken.getSubject(); //extract username of requester from the token
                            String username = (String) message.getObjContents().get(0); //extract username of the new group member from message
                            String groupname = (String) message.getObjContents().get(1); //Extract the groupname from message
                            //check if the group exists and the user has ownership of the group they are attempting to add a user to and if the user is not already in the group
                            if (my_gs.userList.getUserOwnership(owner).contains(groupname) && my_gs.userList.checkUser(username) && !my_gs.userList.getUserGroups(username).contains(groupname))
                            {
                                my_gs.userList.addGroup(username, groupname); //add membership to group
                                response = new Envelope("OK"); //Success
                            }
                        }
                    }
                    output.writeObject(response);
                } else if (message.getMessage().equals("RUSERFROMGROUP")) //Client wants to remove user from a group
                {
                    if (message.getObjContents().size() < 3) {
                        response = new Envelope("FAIL");
                    } else {
                        response = new Envelope("FAIL");

                        if (message.getObjContents().get(0) != null && message.getObjContents().get(1) != null && message.getObjContents().get(2) != null) {
                            UserToken yourToken = (UserToken) message.getObjContents().get(2); //Extract the token
                            String owner = yourToken.getSubject(); //extract username of requester from the token
                            String username = (String) message.getObjContents().get(0); //extract username of the group member to be removed from message
                            String groupname = (String) message.getObjContents().get(1); //Extract the groupname from message
                            //check if the requester has ownership of the group they are attempting to remove a user from and if the user to be removed exists and if the user is in the group
                            if (my_gs.userList.getUserOwnership(owner).contains(groupname) && my_gs.userList.checkUser(username) && my_gs.userList.getUserGroups(username).contains(groupname))
                            {
                                response = new Envelope("OK"); //Success
                                ArrayList<String> groupsDeleted = new ArrayList<String>();
                                if (owner.equals(username)) 
                                { //if the owner is removing themselves, the group is deleted
                                    my_gs.userList.removeOwnership(username, groupname); //remove member from group
                                    deleteGroup(groupname, (Token) yourToken);
                                    groupsDeleted.add(groupname);
                                } else 
                                {
                                    my_gs.userList.removeGroup(username, groupname); //remove member from group
                                }
                                response.addObject((List<String>)groupsDeleted);
                            }
                        }
                    }
                    output.writeObject(response);
                } else if (message.getMessage().equals("DISCONNECT")) //Client wants to disconnect
                {
                    socket.close(); //Close the socket
                    proceed = false; //End this communication loop
                } else {
                    response = new Envelope("FAIL"); //Server does not understand client request
                    output.writeObject(response);
                }
            } while (proceed);
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }

    //Method to create tokens
    private UserToken createToken(String username) {
        //Check that user exists
        if (my_gs.userList.checkUser(username)) {
            //Issue a new token with server's name, user's name, and user's groups
            UserToken yourToken = new Token(my_gs.name, username, my_gs.userList.getUserGroups(username));
            return yourToken;
        } else {
            return null;
        }
    }

    //Method to create a user
    private boolean createUser(String username, String password, UserToken yourToken) {
        String requester = yourToken.getSubject();

        //Check if requester exists
        if (my_gs.userList.checkUser(requester)) {
            //Get the user's groups
            ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
            //requester needs to be an administrator
            if (temp.contains("ADMIN")) {
                //Does user already exist?
                if (my_gs.userList.checkUser(username)) {
                    return false; //User already exists
                } else {
                    my_gs.userList.addUser(username, password);
                    return true;
                }
            } else {
                return false; //requester not an administrator
            }
        } else {
            return false; //requester does not exist
        }
    }

    //Method to delete a user
    private List<String> deleteUser(String username, UserToken yourToken) {
        String requester = yourToken.getSubject();

        //Does requester exist?
        if (my_gs.userList.checkUser(requester)) {
            ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
            //requester needs to be an administer
            if (temp.contains("ADMIN")) {
                //Does user exist?
                if (my_gs.userList.checkUser(username)) {
                    //User needs deleted from the groups they belong
                    ArrayList<String> deleteFromGroups = new ArrayList<String>();

                    //This will produce a hard copy of the list of groups this user belongs
                    for (int index = 0; index < my_gs.userList.getUserGroups(username).size(); index++) {
                        deleteFromGroups.add(my_gs.userList.getUserGroups(username).get(index));
                    }

                    //Delete the user from the groups
                    for (int index = 0; index < deleteFromGroups.size(); index++) {
                        my_gs.userList.removeGroup(username, deleteFromGroups.get(index));
                    }

                    //If groups are owned, they must be deleted
                    ArrayList<String> deleteOwnedGroup = new ArrayList<String>();

                    //Make a hard copy of the user's ownership list
                    for (int index = 0; index < my_gs.userList.getUserOwnership(username).size(); index++) {
                        deleteOwnedGroup.add(my_gs.userList.getUserOwnership(username).get(index));
                    }

                    //Delete owned groups
                    for (int index = 0; index < deleteOwnedGroup.size(); index++) {
                        //Use the delete group method. Token must be created for this action
                        deleteGroup(deleteOwnedGroup.get(index), new Token(my_gs.name, username, deleteOwnedGroup));
                    }

                    //Delete the user from the user list
                    my_gs.userList.deleteUser(username);

                    return (List<String>)deleteOwnedGroup;
                } else {
                    return null; //User does not exist

                }
            } else {
                return null; //requester is not an administer
            }
        } else {
            return null; //requester does not exist
        }
    }

    private boolean deleteGroup(String groupname, Token yourToken) {
        ArrayList<String> groupMembers = my_gs.userList.getMembers(groupname);
        for (String member : groupMembers) {
            my_gs.userList.removeGroup(member, groupname);
        }
        return true;
    }
}
