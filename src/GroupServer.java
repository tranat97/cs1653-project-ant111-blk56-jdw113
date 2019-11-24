/* Group server. Server loads the users from UserList.bin.
*  If user list does not exists, it creates a new list and makes the user the server administrator.
*  On exit, the server saves the user list to file.
*/

import java.net.ServerSocket;
import java.net.Socket;
import java.io.*;
import java.util.*;
import java.security.KeyPair;

public class GroupServer extends Server
{
	public static final int SERVER_PORT = 8765;
	public Crypto crypto;
	public UserList userList;
	public KeyPair RSAKeys;

	public GroupServer()
	{
		super(SERVER_PORT, "ALPHA");
	}

	public GroupServer(int _port)
	{
		super(_port, "ALPHA");
	}

	public void start()
	{
		crypto = new Crypto();
		// Overwrote server.start() because if no user file exists, initial admin account needs to be created

		String userFile = "UserList.bin";
		Scanner console = new Scanner(System.in);
		ObjectInputStream userStream;

		//This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		runtime.addShutdownHook(new ShutDownListener(this));

		//Open user file to get user list
		try
		{
			FileInputStream fis = new FileInputStream(userFile);
			userStream = new ObjectInputStream(fis);
			userList = (UserList)userStream.readObject();
			System.out.println("UserFile found...");
		} catch(FileNotFoundException e) {
			System.out.println("UserList File Does Not Exist. Creating UserList...");
			System.out.println("No users currently exist. Your account will be the administrator.");
			boolean validUserName = false;
			String username;
			do {
				System.out.print("Enter your username: ");
				username = console.nextLine();
				if (invalidCharacters(username)) {
					System.out.println("Invalid username, cannot contain \':\'");
				} else {
					validUserName = true;
				}
			} while (!validUserName);
			System.out.print("Enter your password: ");
			String password = console.nextLine();

			//Create a new list, add current user to the ADMIN group. They now own the ADMIN group.
			userList = new UserList();
			userList.addUser(username, password);
			userList.addGroup(username, "ADMIN");
			userList.addOwnership(username, "ADMIN");
		} catch(IOException e) {
			System.out.println("Error reading from UserList file");
			System.exit(-1);
		} catch(ClassNotFoundException e) {
			System.out.println("Error reading from UserList file");
			System.exit(-1);
		}

		// reading in saved RSA keys, or generating if missing
		RSAKeys = crypto.getRSAKeys("GroupPublic.rsa", "GroupPrivate.rsa");
		System.out.println("Your public key: " + crypto.fingerprint(RSAKeys.getPublic()));
		//Autosave Daemon. Saves lists every 5 minutes
		AutoSave aSave = new AutoSave(this);
		aSave.setDaemon(true);
		aSave.start();

		//This block listens for connections and creates threads on new connections
		try {
			final ServerSocket serverSock = new ServerSocket(port);
			Socket sock = null;
			GroupThread thread = null;

			while(true) {
				sock = serverSock.accept();
				thread = new GroupThread(sock, this);
				thread.start();
			}
		} catch(Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}

	public boolean invalidCharacters(String s)
	{
		return s.contains(":");
	}
}

//This thread saves the user list
class ShutDownListener extends Thread
{
	public GroupServer my_gs;

	public ShutDownListener (GroupServer _gs)
	{
		my_gs = _gs;
	}

	public void run()
	{
		System.out.println("Shutting down server");
		ObjectOutputStream outStream;
		try {
			outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
			outStream.writeObject(my_gs.userList);
		} catch(Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
}

class AutoSave extends Thread
{
	public GroupServer my_gs;

	public AutoSave (GroupServer _gs)
	{
		my_gs = _gs;
	}

	public void run()
	{
		do {
			try {
				Thread.sleep(300000); //Save user lists every 5 minutes
				System.out.println("Autosave user lists...");
				ObjectOutputStream outStream;
				try {
					outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
					outStream.writeObject(my_gs.userList);
				} catch(Exception e) {
					System.err.println("Error: " + e.getMessage());
					e.printStackTrace(System.err);
				}
			} catch(Exception e) {
				System.out.println("Autosave Interrupted");
			}
		} while(true);
	}
}
