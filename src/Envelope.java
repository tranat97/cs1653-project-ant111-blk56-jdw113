import java.util.ArrayList;

public class Envelope implements java.io.Serializable
{
	private static final long serialVersionUID = -7726335089122193103L;
	private String msg;
	private byte[] hmac;
	private ArrayList<Object> objContents = new ArrayList<Object>();

	public Envelope(String text)
	{
		msg = text;
	}

	public String getMessage()
	{
		return msg;
	}

	public byte[] getHMAC()
	{
		return hmac;
	}

	public void setHMAC(byte[] hmac)
	{
		this.hmac = hmac;
	}

	public ArrayList<Object> getObjContents()
	{
		return objContents;
	}

	public void addObject(Object object)
	{
		objContents.add(object);
	}
}
