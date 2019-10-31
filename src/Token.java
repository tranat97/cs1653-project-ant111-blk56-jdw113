import java.util.List;
import java.util.ArrayList;
import java.io.Serializable;

public class Token implements UserToken, Serializable
{
	private String issuer;
	private String subject;
	private List<String> groups;
	private byte[] signature;

	public Token(String issuer, String subject, List<String> groups)
	{
		this.issuer = issuer;
		this.subject = subject;
		this.groups = new ArrayList<String>(groups);
	}

    /**
     * This method should return a string describing the issuer of
     * this token.  This string identifies the group server that
     * created this token.  For instance, if "Alice" requests a token
     * from the group server "Server1", this method will return the
     * string "Server1".
     *
     * @return The issuer of this token
     *
     */
    public String getIssuer()
	{
		return this.issuer;
	}


    /**
     * This method should return a string indicating the name of the
     * subject of the token.  For instance, if "Alice" requests a
     * token from the group server "Server1", this method will return
     * the string "Alice".
     *
     * @return The subject of this token
     *
     */
    public String getSubject()
	{
		return this.subject;
	}


    /**
     * This method extracts the list of groups that the owner of this
     * token has access to.  If "Alice" is a member of the groups "G1"
     * and "G2" defined at the group server "Server1", this method
     * will return ["G1", "G2"].
     *
     * @return The list of group memberships encoded in this token
     *
     */
    public List<String> getGroups()
	{
		return new ArrayList<String>(groups);
	}

	public void setSignature(byte[] signature)
	{
		this.signature = signature;
	}

	public byte[] getSignature()
	{
		return this.signature;
	}

	public String toString()
	{
		final StringBuilder sb = new StringBuilder();
		sb.append(issuer + ":" + subject + ":");
		for (String s : groups)
		{
			sb.append(s + ":");
		}
		return sb.toString();
	}

}
