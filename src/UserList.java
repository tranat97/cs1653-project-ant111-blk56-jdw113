/* This list represents the users on the server */
import java.security.Key;
import java.util.*;
public class UserList implements java.io.Serializable
{
	private static final long serialVersionUID = 7600343803563417992L;
	private Hashtable<String, User> list = new Hashtable<String, User>();
	private Hashtable<String, ArrayList<Key>> keyList = new Hashtable<String, ArrayList<Key>>();
	private Hashtable<String, Boolean> status = new Hashtable<String, Boolean>(); //True=valid key; false=new key needs to be generated
	private Crypto crypto = new Crypto();

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
		if (!checkUser(username)) {
			return false;
		}
		return list.get(username).checkPassword(password);
	}

	public synchronized boolean setPassword(String username, String password)
	{
		if (checkUser(username) && password != null) {
			list.get(username).setPassword(password);
			return true;
		} else {
			return false;
		}
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
		status.replace(groupname, false); //This group will need to generate a new key next time it is requested
	}
	
	//Only called when a new group is being created
	public synchronized void addOwnership(String user, String groupname)
	{
		list.get(user).addOwnership(groupname);
		keyList.put(groupname, new ArrayList<Key>());
		status.put(groupname, false);
	}

	//Only called when a group is being deleted
	public synchronized void removeOwnership(String user, String groupname)
	{
		list.get(user).removeOwnership(groupname);
		keyList.remove(groupname);
		status.remove(groupname);
	}

	public synchronized ArrayList<String> getMembers(String groupname)
	{
		ArrayList<String> members = new ArrayList<String>();
		for (String user : list.keySet()) {
			if (list.get(user).getGroups().contains(groupname)) {
				members.add(user);
			}
		}
		return members;
	}
	
	public synchronized Key getKey(String groupname, Integer n)
	{
        try {
            if (keyList.containsKey(groupname)) {
                if (n<0) { //get most recent key
                    if (status.get(groupname)) {
                        ArrayList<Key> keys = keyList.get(groupname);
                        return keys.get(keys.size()-1);
                    } else {
                        Key newKey = crypto.generateAESKey();
                        keyList.get(groupname).add(newKey);
                        status.replace(groupname, true);
                        return newKey;
                    }
                } else { 
                    ArrayList<Key> keys = keyList.get(groupname);
                    return keys.get(n);
                }
            }
        } catch(Exception e) {
            return null;
        }
		return null;
	}
    
    public synchronized Boolean getStatus(String groupname)
    {
        return status.get(groupname);
    }

	public synchronized Integer getNewest(String groupname) {
		return keyList.get(groupname).size()-1;
	}
	
	class User implements java.io.Serializable
	{
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

		public void setPassword(String password)
		{
			this.password = password;
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
			if(!groups.isEmpty() && groups.contains(group)) {
				groups.remove(groups.indexOf(group));
			}
		}

		public void addOwnership(String group)
		{
			ownership.add(group);
		}

		public void removeOwnership(String group)
		{
			if(!ownership.isEmpty() && ownership.contains(group)) {
				ownership.remove(ownership.indexOf(group));
			}
		}
	}
}
