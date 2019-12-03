import java.security.Key;
/**
 * Stores key information
 * @author trana
 */
public class KeyInfo {
    final private Key key;
    final private Integer n;
    
    public KeyInfo(Key k, int num) 
    {
        key = k;
        n = num;
    }
    
    public Key getKey()
    {
        return key;
    }
    
    public Integer getKeyNum()
    {
        return n;
    }
}
