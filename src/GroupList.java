/**
 *
 * @author trana
 */
import java.util.*;
public class GroupList implements java.io.Serializable {
    
    private static final long serialVersionUID = 7600343803563417992L;
    private Hashtable<String, Group> list = new Hashtable<String, Group>();
		
    public synchronized void addGroup(String groupname)
    {
        Group newGroup = new Group();
        list.put(groupname, newGroup);
    }
		
    public synchronized void deleteGroup(String groupname)
    {
    	list.remove(groupname);
    }
		
    public synchronized boolean checkGroup(String groupname)
    {
    	if(list.containsKey(groupname))
    	{
            return true;
        }
	else
	{
            return false;
	}
    }
		
    public synchronized ArrayList<String> getGroupMembers(String groupname)
    {
    	return list.get(groupname).getMembers();
    }
    
    public synchronized String getGroupOwnership(String groupname)
    {
    	return list.get(groupname).getOwnership();
    }
    
    public synchronized void addMember(String group, String membername)
    {
    	list.get(group).addMember(membername);
    }
		
    public synchronized void removeMember(String group, String membername)
    {
    	list.get(group).removeMember(membername);
    }
		
    public synchronized void addOwnership(String group, String membername)
    {
    	list.get(group).addOwnership(membername);
    }
    
    public synchronized void removeOwnership(String group, String membername)
    {
    	list.get(group).removeOwnership(membername);
    }
		
	
    class Group implements java.io.Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = -6699986336399821598L;
	private ArrayList<String> members;
	private String owner;
	
	public Group()
	{
            members = new ArrayList<String>();
            owner = null;
	}
	
	public ArrayList<String> getMembers()
	{
            return members;
	}
	
	public String getOwnership()
	{
            return owner;
	}
	
	public void addMember(String member)
	{
            members.add(member);
        }
            
        public void removeMember(String member)
	{
            if(!members.isEmpty())
            {
                if(members.contains(member))
                {
                    members.remove(members.indexOf(member));
                }
            }
	}
		
	public void addOwnership(String member)
	{
            owner = member;
	}
		
	public void removeOwnership(String group)
	{
            owner = null;
        }
    }
    
}
