/* This list represents the users on the server */
import java.util.*;


	public class UserList implements java.io.Serializable {
	
		/**
		 * 
		 */
		private static final long serialVersionUID = 7600343803563417992L;
		private Hashtable<String, User> list = new Hashtable<String, User>();
		
		public synchronized void addUser(String username, String password)
		{
			User newUser = new User(password);
			list.put(username, newUser);
		}
		
		public synchronized void deleteUser(String username)
		{
			list.remove(username);
		}
		
		public synchronized boolean checkUser(String username)
		{
			return list.containsKey(username);
		}

		public synchronized boolean checkPassword(String username, String password)
		{
			return list.get(username).checkPassword(password);
		}
		
		public synchronized ArrayList<String> getUserGroups(String username)
		{
			return list.get(username).getGroups();
		}
		
		public synchronized ArrayList<String> getUserOwnership(String username)
		{
			return list.get(username).getOwnership();
		}
		
		public synchronized void addGroup(String user, String groupname)
		{
			list.get(user).addGroup(groupname);
		}
		
		public synchronized void removeGroup(String user, String groupname)
		{
			list.get(user).removeGroup(groupname);
		}
		
		public synchronized void addOwnership(String user, String groupname)
		{
			list.get(user).addOwnership(groupname);
		}
		
		public synchronized void removeOwnership(String user, String groupname)
		{
			list.get(user).removeOwnership(groupname);
		}
		
		public synchronized ArrayList<String> getMembers(String groupname)
		{
			ArrayList<String> members = new ArrayList<String>();
			for (String user : list.keySet())
			{
				if (list.get(user).getGroups().contains(groupname))
				{
					members.add(user);
				}
			}
			return members;
		}
	
	class User implements java.io.Serializable {

		private static final long serialVersionUID = -6699986336399821598L;
		private ArrayList<String> groups;
		private ArrayList<String> ownership;
		private String password;
		
		public User(String password)
		{
			groups = new ArrayList<String>();
			ownership = new ArrayList<String>();
			this.password = password;
		}
		
		public boolean checkPassword(String password)
		{
			return this.password.equals(password);
		}

		public ArrayList<String> getGroups()
		{
			return groups;
		}
		
		public ArrayList<String> getOwnership()
		{
			return ownership;
		}
		
		public void addGroup(String group)
		{
			groups.add(group);
		}
		
		public void removeGroup(String group)
		{
			if(!groups.isEmpty() && groups.contains(group))
			{
				groups.remove(groups.indexOf(group));
			}
		}
		
		public void addOwnership(String group)
		{
			ownership.add(group);
		}
		
		public void removeOwnership(String group)
		{
			if(!ownership.isEmpty() && ownership.contains(group))
			{
				ownership.remove(ownership.indexOf(group));
			}
		}
	}
}	
