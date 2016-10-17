import com.tudelft.paillier.PaillierKeyMismatchException;
import com.tudelft.paillier.PaillierPrivateKey;
import com.tudelft.paillier.PaillierPrivateKeyRing;
import org.json.simple.parser.ParseException;
import org.junit.Assert;
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

@SuppressWarnings("Duplicates")
public class PaillierPrivateKeyRingTest
{
	private String                 password;
	private String                 longPassword;
	private PaillierPrivateKeyRing skRing;
	private PaillierPrivateKey     sk0;
	private PaillierPrivateKey     sk1;
	private PaillierPrivateKey     sk2;
	private PaillierPrivateKey     sk3;
	
	public PaillierPrivateKeyRingTest() throws Exception
	{
		password = "testPass";
		longPassword = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut lab";
		skRing = new PaillierPrivateKeyRing(password);
		sk0 = PaillierPrivateKey.create(1024);
		sk1 = PaillierPrivateKey.create(1024);
		sk2 = PaillierPrivateKey.create(1024);
		sk3 = PaillierPrivateKey.create(1024);
		
		skRing.put(0, sk0);
		skRing.put(1, sk1);
		skRing.put(2, sk2);
		skRing.put(3, sk3);
		
		if (PaillierPrivateKeyRing.keyDir.toFile().exists())
		{
			if (PaillierPrivateKeyRing.keyRingFile.toFile().exists())
			{
				PaillierPrivateKeyRing.keyRingFile.toFile().delete();
				PaillierPrivateKeyRing.AESKeyFile.toFile().delete();
				PaillierPrivateKeyRing.passHashFile.toFile().delete();
			}
		}
		PaillierPrivateKeyRing.keyDir.toFile().delete();
		skRing.writeToFile();
	}
	
	@Test
	public void testEmptyRing() throws Exception
	{
		PaillierPrivateKeyRing skRing = new PaillierPrivateKeyRing("");
		
		Assert.assertNull(skRing.get(1));
		
		try
		{
			skRing.writeToFile();
		}
		catch (IOException e)
		{
			fail("Failed to write to " + PaillierPrivateKeyRing.keyRingFile);
		}
		File file = PaillierPrivateKeyRing.keyRingFile.toFile();
		
		Assert.assertEquals(32, file.length()); //Salt length and block size are both 16 bytes
		
		try
		{
			PaillierPrivateKeyRing skRing2 = PaillierPrivateKeyRing.loadFromFile("");
			Assert.assertEquals(skRing, skRing2);
		}
		catch (IOException e) { fail("Failed to read from " + PaillierPrivateKeyRing.keyRingFile); }
		catch (ParseException e) { fail("Invalid json in " + PaillierPrivateKeyRing.keyRingFile); }
	}
	
	@Test
	public void testWrongPassword()
			throws IOException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			       IllegalBlockSizeException, ParseException, NoSuchPaddingException, InvalidKeyException,
			       InvalidKeySpecException
	{
		try
		{
			PaillierPrivateKeyRing.loadFromFile(longPassword);
		}
		catch (PaillierKeyMismatchException e)
		{
			assertEquals(e.getMessage(), "Invalid passphrase, could not decrypt keyring.");
		}
	}
	
	@Test
	public void testKeyStorageAndRetrieval()
	{
		Assert.assertEquals(4, skRing.size());
		Assert.assertEquals(sk0, skRing.get(0));
		Assert.assertEquals(sk1, skRing.get(1));
		Assert.assertEquals(sk2, skRing.get(2));
		Assert.assertEquals(sk3, skRing.get(3));
	}
	
	@Test
	public void testPersistentStorage() throws Exception
	{
		PaillierPrivateKeyRing skRing2 = PaillierPrivateKeyRing.loadFromFile(password);
		
		Assert.assertEquals(skRing, skRing2);
	}
}
