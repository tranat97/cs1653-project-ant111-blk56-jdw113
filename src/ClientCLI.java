import java.util.Scanner;
import java.util.List;
import java.security.Key;

public class ClientCLI
{
	final static Scanner scan = new Scanner(System.in);
	final static GroupClient groupClient = new GroupClient();
	final static FileClient fileClient = new FileClient();
	static UserToken tokenGS;
	static UserToken tokenFS;
	static String username;
	static String password;

	public static void main(String[] args)
	{
		//connect("GroupServer", groupClient);
		groupClient.connect("localhost", 8765);
		if (!groupClient.handshake()) {
			groupClient.disconnect();
			System.out.println("Handshake failed");
			System.exit(1);
		}
		System.out.println("Handshake Successful; Connected to Group Server...");
		System.out.println();

		//connect("FileServer", fileClient);
		fileClient.connect("localhost", 4321);
		if(!fileClient.handshake()){
			fileClient.disconnect();
			System.out.println("Handshake failed");
			System.exit(1);
		}
		System.out.println("Handshake Successful; Connected to File Server...");
		System.out.println();
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
			} else if (command.equals("changepassword")) {
				changePassword();
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
		UserToken recievedGS;
		UserToken recievedFS;
		do {
			System.out.print("Enter username: ");
			username = scan.nextLine();
			System.out.print("Enter password: ");
			password = scan.nextLine();
			recievedGS = groupClient.getToken(username, password, groupClient.getServerPublicKey());
			recievedFS = groupClient.getToken(username, password, fileClient.getServerPublicKey());
			if (recievedGS == null || recievedFS == null) {
				System.out.println("Invalid credentials");
			}
		} while (recievedGS == null || recievedFS == null);
		tokenGS = recievedGS;
		tokenFS = recievedFS;
	}

	public static void refreshToken()
	{
		tokenGS = groupClient.getToken(username, password, groupClient.getServerPublicKey());
		tokenFS = groupClient.getToken(username, password, fileClient.getServerPublicKey());
	}

	public static void printHelp()
	{
		System.out.println("GroupServer commands:");
		System.out.println("\tcreateuser\n\tdeleteuser\n\tcreategroup\n\tdeletegroup");
		System.out.println("\taddusertogroup\n\tdeleteuserfromgroup\n\tlistmembers");
		System.out.println("FileServer commands:");
		System.out.println("\tlistfiles\n\tupload\n\tdownload\n\tdelete\n\t");
		System.out.println("Other commands:");
		System.out.println("\tchangeuser\n\tchangepassword\n\thelp\n\texit");
	}

	public static void changePassword()
	{
		System.out.print("Enter your new password: ");
		final String newPassword = scan.nextLine();
		if (groupClient.changePassword(newPassword, tokenGS)) {
			password = newPassword;
			System.out.println("Successfully changed password");
		} else {
			System.out.println("Failed to change password");
		}
	}

	public static void createUser()
	{
		System.out.print("Enter new user's username: ");
		final String username = scan.nextLine();
		System.out.print("Enter new user's password: ");
		final String password = scan.nextLine();
		if (groupClient.createUser(username, password, tokenGS)) {
			System.out.println("Successfully created user: " + username);
		} else {
			System.out.println("Failed to create user: " + username);
		}
	}

	public static void deleteUser()
	{
		System.out.print("Enter username to be deleted: ");
		final String username = scan.nextLine();
		UserToken groupsDeleted = groupClient.deleteUser(username, tokenGS, fileClient.getServerPublicKey());
		if (groupsDeleted != null) {
			System.out.println("Successfully deleted user: " + username);
			if (!groupsDeleted.getGroups().isEmpty()) {
				System.out.println(username + "'s owned groups: " + groupsDeleted.getGroups());
				fileClient.condFileDelete(groupsDeleted);
			}
		} else {
			System.out.println("Failed to delete user: " + username);
		}
	}

	public static void createGroup()
	{
		System.out.print("Enter new group's name: ");
		final String groupName = scan.nextLine();
		if (groupClient.createGroup(groupName, tokenGS)) {
			System.out.println("Successfully created group: " + groupName);
		} else {
			System.out.println("Failed to create group: " + groupName);
		}
	}

	public static void deleteGroup()
	{
		System.out.print("Enter the name of the group to be deleted: ");
		final String groupName = scan.nextLine();
		UserToken groupsDeleted = groupClient.deleteGroup(groupName, tokenGS, fileClient.getServerPublicKey());
		if (groupsDeleted != null) {
			fileClient.condFileDelete(groupsDeleted);
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
		if (groupClient.addUserToGroup(username, groupName, tokenGS)) {
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
		UserToken groupsDeleted = groupClient.deleteUserFromGroup(username, groupName, tokenGS, fileClient.getServerPublicKey());
		if (groupsDeleted != null) {
			System.out.println("Successfully deleted " + username + " from group " + groupName);
			if (!groupsDeleted.getGroups().isEmpty()) {
				System.out.println(username + " was the owner of " + groupName + "; The group is now deleted...");
				fileClient.condFileDelete(groupsDeleted);
			}
		} else {
			System.out.println("Failed to delete " + username + " from group " + groupName);
		}
	}

	public static void listMembers()
	{
		System.out.print("Enter the group name to list members from: ");
		final String groupName = scan.nextLine();
		final List<String> members = groupClient.listMembers(groupName, tokenGS);
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
		final List<String> files = fileClient.listFiles(tokenFS);
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
		KeyInfo info = groupClient.keyRequest(groupName, new Integer(-1), tokenGS);
        if (info!=null) {
            Key key = info.getKey();
            Integer n = info.getKeyNum();
            if (fileClient.upload(source, destination, groupName, tokenFS, key, n)) {
                System.out.println("Successfully uploaded: " + source);
            } else {
                System.out.println("Failed to upload: " + source);
            }
        }
	}

	public static void download()
	{
		System.out.print("Enter the source file's name: ");
		final String source = scan.nextLine();
		System.out.print("Enter the destination file's name: ");
		final String destination = scan.nextLine();
		System.out.print("Enter the group name the file belongs to: ");
		final String groupname = scan.nextLine();
		//Retrieve required key
		Integer keyNum = fileClient.keyRequest(source, tokenFS);
		if (keyNum == null) {
			return;
		}
		KeyInfo info = groupClient.keyRequest(groupname, keyNum, tokenGS);
		if (info != null) {
            Key key = info.getKey();
			if (fileClient.download(source, destination, tokenFS, key)) {
				System.out.println("Successfully downloaded: " + source);
			} else {
				System.out.println("Failed to downloaded: " + source);
			}
		}
		
		//Decrypt the file
	}

	public static void delete()
	{
		System.out.print("Enter the name of the file to delete: ");
		final String toDelete = scan.nextLine();
		if (fileClient.delete(toDelete, tokenFS)) {
			System.out.println("Successfully deleted: " + toDelete);
		} else {
			System.out.println("Failed to delete: " + toDelete);
		}
	}
}
