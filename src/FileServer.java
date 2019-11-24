/* FileServer loads files from FileList.bin.  Stores files in shared_files directory. */
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.Key;
import java.security.PublicKey;

public class FileServer extends Server
{
	public static final int SERVER_PORT = 4321;
	public Crypto crypto;
	public static FileList fileList;
	public KeyPair RSAKeys;
	public PublicKey trustedGroupServer;
	
	public FileServer()
	{
		super(SERVER_PORT, "FilePile");
	}

	public FileServer(int _port)
	{
		super(_port, "FilePile");
	}

	public void start()
	{
		crypto = new Crypto();

		trustedGroupServer = crypto.getPublicKey("GroupPublic.rsa");
		if (trustedGroupServer == null) {
			System.out.println("Missing GroupPublic.rsa file, cannot trust any tokens");
			System.exit(-1);
		} else {
			System.out.println("Found GroupPublic.rsa");
		}

		String fileFile = "FileList.bin";
		ObjectInputStream fileStream;

		//This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		Thread catchExit = new Thread(new ShutDownListenerFS());
		runtime.addShutdownHook(catchExit);
		
		//Open user file to get user list
		try {
			FileInputStream fis = new FileInputStream(fileFile);
			fileStream = new ObjectInputStream(fis);
			fileList = (FileList)fileStream.readObject();
		} catch(FileNotFoundException e) {
			System.out.println("FileList Does Not Exist. Creating FileList...");
			fileList = new FileList();
		} catch(IOException e) {
			System.out.println("Error reading from FileList file");
			System.exit(-1);
		} catch(ClassNotFoundException e) {
			System.out.println("Error reading from FileList file");
			System.exit(-1);
		}

		File file = new File("shared_files");
		if (file.mkdir()) {
			System.out.println("Created new shared_files directory");
		} else if (file.exists()){
			System.out.println("Found shared_files directory");
		} else {
			System.out.println("Error creating shared_files directory");
		}
		//Read in saved RSA Key pair or or generate new pair
		RSAKeys = crypto.getRSAKeys("FilePublic.rsa", "FilePrivate.rsa");
		System.out.println("Your Public Key: " + crypto.fingerprint(RSAKeys.getPublic()));
		//Autosave Daemon. Saves lists every 5 minutes
		AutoSaveFS aSave = new AutoSaveFS();
		aSave.setDaemon(true);
		aSave.start();

		boolean running = true;
		try {
			final ServerSocket serverSock = new ServerSocket(port);
			System.out.printf("%s up and running\n", this.getClass().getName());

			Socket sock = null;
			Thread thread = null;

			while(running) {
				sock = serverSock.accept();
				thread = new FileThread(sock,this);
				thread.start();
			}

			System.out.printf("%s shut down\n", this.getClass().getName());
		} catch(Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
	
//	public Key getPublic()
//	{
//		return RSAKeys.getPublic();
//	}
}

//This thread saves user and group lists
class ShutDownListenerFS implements Runnable
{
	public void run()
	{
		System.out.println("Shutting down server");
		ObjectOutputStream outStream;

		try {
			outStream = new ObjectOutputStream(new FileOutputStream("FileList.bin"));
			outStream.writeObject(FileServer.fileList);
		} catch(Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
}

class AutoSaveFS extends Thread
{
	public void run()
	{
		do {
			try {
				Thread.sleep(300000); //Save group and user lists every 5 minutes
				System.out.println("Autosave file list...");
				ObjectOutputStream outStream;
				try {
					outStream = new ObjectOutputStream(new FileOutputStream("FileList.bin"));
					outStream.writeObject(FileServer.fileList);
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
