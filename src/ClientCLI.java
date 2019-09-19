import java.util.Scanner;
import java.util.List;

public class ClientCLI
{
	final static Scanner scan = new Scanner(System.in);
	final static GroupClient groupClient = new GroupClient();
	final static FileClient fileClient = new FileClient();
	static UserToken token;

	public static void main(String[] args)
	{
		connect("GroupServer", groupClient);
		connect("FileServer", fileClient);
//		groupClient.connect("localhost", 8765);
//		fileClient.connect("localhost", 4321);
		login();
		
		String command;
		System.out.print("Type help to get a list of commands");
		do
		{
			System.out.print("\n> ");
			command = scan.nextLine().toLowerCase();

			if (command.equals("help")) { printHelp(); }
			else if (command.equals("changeuser")) { login(); }
			else if (command.equals("createuser")) { createUser(); }
			else if (command.equals("deleteuser")) { deleteUser(); }
			else if (command.equals("creategroup")) { createGroup(); }
			else if (command.equals("deletegroup")) { deleteGroup(); }
			else if (command.equals("addusertogroup")) { addUserToGroup(); }
			else if (command.equals("deleteuserfromgroup")) { deleteUserFromGroup(); }
			else if (command.equals("listmembers")) { listMembers(); }
			else if (command.equals("listfiles")) { listFiles(); }
			else if (command.equals("upload")) { upload(); }
			else if (command.equals("download")) { download(); }
			else if (command.equals("delete")) { delete(); }
			else if (!command.equals("exit"))
			{
				System.out.println("Invalid command");
			}
		}
		while (!command.equals("exit"));

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
		if (!c.connect(address, port))
		{
			System.out.printf("Failed to connect to %s " + address + ":" + port + "\n", type);
			System.exit(1);
		}
	}

	public static void login()
	{
		UserToken recieved;
		do
		{
			System.out.print("Enter username: ");
			final String username = scan.nextLine();
			recieved = groupClient.getToken(username);
			if (recieved == null)
			{
				System.out.println("Invalid username");
			}
		}
		while(recieved == null);
		token = recieved;
	}

	public static void printHelp()
	{
		System.out.println("GroupServer commands:");
		System.out.println("\tcreateuser\n\tdeleteuser\n\tcreategroup\n\tdeletegroup");
		System.out.println("\taddusertogroup\n\tdeleteuserfromgroup\n\tlistmembers");
		System.out.println("FileServer commands:");
		System.out.println("\tlistfiles\n\tupload\n\tdownload\n\tdelete\n\t");
		System.out.println("Other commands:");
		System.out.println("\tchangeuser\n\thelp");
	}

	public static void createUser()
	{
		System.out.print("Enter new user's username: ");
		final String username = scan.nextLine();
		if (groupClient.createUser(username, token))
		{
			System.out.println("Successfully created user: " + username);
		}
		else
		{
			System.out.println("Failed to create user: " + username);
		}
	}

	public static void deleteUser()
	{
		System.out.print("Enter username to be deleted: ");
		final String username = scan.nextLine();
		if (groupClient.deleteUser(username, token))
		{
			System.out.println("Successfully deleted user: " + username);
		}
		else
		{
			System.out.println("Failed to delete user: " + username);
		}
	}

	public static void createGroup()
	{
		System.out.print("Enter new group's name: ");
		final String groupName = scan.nextLine();
		if (groupClient.createGroup(groupName, token))
		{
			System.out.println("Successfully created group: " + groupName);
		}
		else
		{
			System.out.println("Failed to create group: " + groupName);
		}
	}

	public static void deleteGroup()
	{
		System.out.print("Enter the name of the group to be deleted: ");
		final String groupName = scan.nextLine();
		if (groupClient.deleteGroup(groupName, token))
		{
			System.out.println("Successfully deleted group: " + groupName);
		}
		else
		{
			System.out.println("Failed to delete group: " + groupName);
		}
	}

	public static void addUserToGroup()
	{
		System.out.println("Enter user's username: ");
		final String username = scan.nextLine();
		System.out.println("Enter the group name to add " + username + " to");
		final String groupName = scan.nextLine();
		if (groupClient.addUserToGroup(username, groupName, token))
		{
			System.out.println("Successfully added " + username + " to group " + groupName);
		}
		else
		{
			System.out.println("Failed to add " + username + " to group " + groupName);
		}
	}

	public static void deleteUserFromGroup()
	{
		System.out.println("Enter user's username: ");
		final String username = scan.nextLine();
		System.out.println("Enter the group name to delete " + username + " from");
		final String groupName = scan.nextLine();
		if (groupClient.deleteUserFromGroup(username, groupName, token))
		{
			System.out.println("Successfully deleted " + username + " from group " + groupName);
		}
		else
		{
			System.out.println("Failed to delete " + username + " from group " + groupName);
		}
	}

	public static void listMembers()
	{
		System.out.println("Enter the group name to list members from: ");
		final String groupName = scan.nextLine();
		final List<String> members = groupClient.listMembers(groupName, token);
		if (members != null)
		{
			for (final String member : members)
			{
				System.out.println("\t" + member);
			}
		}
		else
		{
			System.out.println("Failed to list members of " + groupName);
		}
	}

	public static void listFiles()
	{
		final List<String> files = fileClient.listFiles(token);
		if (files.size() > 0)
		{
			for (final String file : files)
			{
				System.out.println("\t" + file);
			}
		}
		else
		{
			System.out.println("You do not have access to any files in the file server");
		}
	}

	public static void upload()
	{
		System.out.print("Enter the source file's path: ");
		final String source = scan.nextLine();
		System.out.print("Enter the destination file's name: ");
		final String destination = scan.nextLine();
		System.out.println("Enter the group name which the file should be shared with: ");
		final String groupName = scan.nextLine();
		if (fileClient.upload(source, destination, groupName, token))
		{
			System.out.println("Successfully uploaded: " + source);
		}
		else
		{
			System.out.println("Failed to upload: " + source);
		}
	}

	public static void download()
	{
		System.out.print("Enter the source file's name: ");
		final String source = scan.nextLine();
		System.out.print("Enter the destination file's name: ");
		final String destination = scan.nextLine();
		if (fileClient.download(source, destination, token))
		{
			System.out.println("Successfully downloaded: " + source);
		}
		else
		{
			System.out.println("Failed to downloaded: " + source);
		}
	}

	public static void delete()
	{
		System.out.print("Enter the name of the file to delete: ");
		final String toDelete = scan.nextLine();
		if (fileClient.delete(toDelete, token))
		{
			System.out.println("Successfully deleted: " + toDelete);
		}
		else
		{
			System.out.println("Failed to delete: " + toDelete);
		}
	}
}
