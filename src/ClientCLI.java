import java.util.Scanner;
import java.util.List;

public class ClientCLI
{

	final static Scanner scan = new Scanner(System.in);
	final static GroupClient groupClient = new GroupClient();
	final static FileClient fileClient = new FileClient();
	static UserToken token;
	static String username;
	static String password;

	public static void main(String[] args)
	{
		//connect("GroupServer", groupClient);
		groupClient.connect("localhost", 8765);
		groupClient.getRSAKeys("ClientPublic.rsa", "ClientPrivate.rsa");
		groupClient.handshake();
		
		boolean connected = true;
		do {
			connect("FileServer", fileClient);
			//fileClient.connect("localhost", 4321);
			if(!fileClient.handshake()){
				fileClient.disconnect();
				connected = false;
			}
		} while(!connected);
        System.out.println("Handshake Successful; Connected to File Server...");
		login();

		String command;
		System.out.println("Type help to get a list of commands\nType exit to quit");
		do {
			System.out.print("\n> ");
			command = scan.nextLine().toLowerCase();

			if (command.equals("help")) {
				printHelp();
			} else if (command.equals("changeuser")) {
				login();
				refreshToken();
			} else if (command.equals("createuser")) {
				createUser();
			} else if (command.equals("deleteuser")) {
				deleteUser();
				refreshToken();
			} else if (command.equals("creategroup")) {
				createGroup();
				refreshToken();
			} else if (command.equals("deletegroup")) {
				deleteGroup();
				refreshToken();
			} else if (command.equals("addusertogroup")) {
				addUserToGroup();
				refreshToken();
			} else if (command.equals("deleteuserfromgroup")) {
				deleteUserFromGroup();
				refreshToken();
			} else if (command.equals("listmembers")) {
				listMembers();
			} else if (command.equals("listfiles")) {
				listFiles();
			} else if (command.equals("upload")) {
				upload();
			} else if (command.equals("download")) {
				download();
			} else if (command.equals("delete")) {
				delete();
			} else if (!command.equals("exit")) {
				System.out.println("Invalid command");
			}
		} while (!command.equals("exit"));

		groupClient.disconnect();
		fileClient.disconnect();
	}

	public static void connect(final String type, final Client c)
	{
		System.out.printf("Enter %s address: ", type);
		final String address = scan.nextLine();
		System.out.printf("Enter %s port: ", type);
		final int port = scan.nextInt();
		scan.nextLine(); // get rid of hanging newline
		if (!c.connect(address, port)) {
			System.out.printf("Failed to connect to %s " + address + ":" + port + "\n", type);
			System.exit(1);
		}
	}

	public static void login()
	{
		UserToken recieved;
		do {
			System.out.print("Enter username: ");
			username = scan.nextLine();
			System.out.print("Enter password: ");
			password = scan.nextLine();
			recieved = groupClient.getToken(username, password);
			if (recieved == null) {
				System.out.println("Invalid credentials");
			}
		} while (recieved == null);
		token = recieved;
	}

	public static void refreshToken()
	{
		token = groupClient.getToken(username, password);
	}

	public static void printHelp()
	{
		System.out.println("GroupServer commands:");
		System.out.println("\tcreateuser\n\tdeleteuser\n\tcreategroup\n\tdeletegroup");
		System.out.println("\taddusertogroup\n\tdeleteuserfromgroup\n\tlistmembers");
		System.out.println("FileServer commands:");
		System.out.println("\tlistfiles\n\tupload\n\tdownload\n\tdelete\n\t");
		System.out.println("Other commands:");
		System.out.println("\tchangeuser\n\thelp\n\texit");
	}

	public static void createUser()
	{
		System.out.print("Enter new user's username: ");
		final String username = scan.nextLine();
		System.out.print("Enter new user's password: ");
		final String password = scan.nextLine();
		if (groupClient.createUser(username, password, token)) {
			System.out.println("Successfully created user: " + username);
		} else {
			System.out.println("Failed to create user: " + username);
		}
	}

	public static void deleteUser()
	{
		System.out.print("Enter username to be deleted: ");
		final String username = scan.nextLine();
		List<String> groupsDeleted = groupClient.deleteUser(username, token);
		if (groupsDeleted != null) {
			System.out.println("Successfully deleted user: " + username);
			if (!groupsDeleted.isEmpty()) {
				System.out.println(username+"'s owned groups: "+groupsDeleted);
				Token newTok = new Token(null, null, groupsDeleted);
				fileClient.condFileDelete(groupsDeleted, newTok);
			}
		} else {
			System.out.println("Failed to delete user: " + username);
		}
	}

	public static void createGroup()
	{
		System.out.print("Enter new group's name: ");
		final String groupName = scan.nextLine();
		if (groupClient.createGroup(groupName, token)) {
			System.out.println("Successfully created group: " + groupName);
		} else {
			System.out.println("Failed to create group: " + groupName);
		}
	}

	public static void deleteGroup()
	{
		System.out.print("Enter the name of the group to be deleted: ");
		final String groupName = scan.nextLine();
		List<String> groupsDeleted = groupClient.deleteGroup(groupName, token);
		if (groupsDeleted != null) {
			Token newTok = new Token(null, null, groupsDeleted);
			fileClient.condFileDelete(groupsDeleted, newTok);
			System.out.println("Successfully deleted group: " + groupName);
		} else {
			System.out.println("Failed to delete group: " + groupName);
		}
	}

	public static void addUserToGroup()
	{
		System.out.print("Enter user's username: ");
		final String username = scan.nextLine();
		System.out.print("Enter the group name to add " + username + " to: ");
		final String groupName = scan.nextLine();
		if (groupClient.addUserToGroup(username, groupName, token)) {
			System.out.println("Successfully added " + username + " to group " + groupName);
		} else {
			System.out.println("Failed to add " + username + " to group " + groupName);
		}
	}

	public static void deleteUserFromGroup()
	{
		System.out.print("Enter user's username: ");
		final String username = scan.nextLine();
		System.out.print("Enter the group name to delete " + username + " from: ");
		final String groupName = scan.nextLine();
		List<String> groupsDeleted = groupClient.deleteUserFromGroup(username, groupName, token);
		if (groupsDeleted != null) {
			System.out.println("Successfully deleted " + username + " from group " + groupName);
			if (!groupsDeleted.isEmpty()) {
				System.out.println(username + " was the owner of " + groupName + "; The group is now deleted...");
				Token newTok = new Token(null, null, groupsDeleted);
				fileClient.condFileDelete(groupsDeleted, newTok);
			}
		} else {
			System.out.println("Failed to delete " + username + " from group " + groupName);
		}
	}

	public static void listMembers()
	{
		System.out.print("Enter the group name to list members from: ");
		final String groupName = scan.nextLine();
		final List<String> members = groupClient.listMembers(groupName, token);
		if (members != null) {
			for (final String member : members) {
				System.out.println("\t" + member);
			}
		} else {
			System.out.println("Failed to list members of " + groupName);
		}
	}

	public static void listFiles()
	{
		final List<String> files = fileClient.listFiles(token);
		if (files != null && files.size() > 0) {
			for (final String file : files) {
				System.out.println("\t" + file);
			}
		} else {
			System.out.println("You do not have access to any files in the file server");
		}
	}

	public static void upload()
	{
		System.out.print("Enter the source file's path: ");
		final String source = scan.nextLine();
		System.out.print("Enter the destination file's name: ");
		final String destination = scan.nextLine();
		System.out.print("Enter the group name which the file should be shared with: ");
		final String groupName = scan.nextLine();
		if (fileClient.upload(source, destination, groupName, token)) {
			System.out.println("Successfully uploaded: " + source);
		} else {
			System.out.println("Failed to upload: " + source);
		}
	}

	public static void download()
	{
		System.out.print("Enter the source file's name: ");
		final String source = scan.nextLine();
		System.out.print("Enter the destination file's name: ");
		final String destination = scan.nextLine();
		if (fileClient.download(source, destination, token)) {
			System.out.println("Successfully downloaded: " + source);
		} else {
			System.out.println("Failed to downloaded: " + source);
		}
	}

	public static void delete()
	{
		System.out.print("Enter the name of the file to delete: ");
		final String toDelete = scan.nextLine();
		if (fileClient.delete(toDelete, token)) {
			System.out.println("Successfully deleted: " + toDelete);
		} else {
			System.out.println("Failed to delete: " + toDelete);
		}
	}
}
