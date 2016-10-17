import com.tudelft.paillier.PaillierPrivateKey;
import com.tudelft.paillier.PaillierPublicKey;
import com.tudelft.paillier.PaillierPublicKeyRing;
import org.json.simple.parser.ParseException;
import org.junit.Assert;
import org.junit.Test;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

import static junit.framework.TestCase.fail;

public class PaillierPublicKeyRingTest
{
	private final PaillierPublicKeyRing pkRing;
	private final PaillierPublicKey     pk0;
	private final PaillierPublicKey     pk1;
	private final PaillierPublicKey     pk2;
	private final PaillierPublicKey     pk3;
	
	
	public PaillierPublicKeyRingTest()
	{
		pkRing = new PaillierPublicKeyRing();
		pk0 = PaillierPrivateKey.create(1024).getPublicKey();
		pk1 = PaillierPrivateKey.create(1024).getPublicKey();
		pk2 = PaillierPrivateKey.create(1024).getPublicKey();
		pk3 = PaillierPrivateKey.create(1024).getPublicKey();
		
		pkRing.put(0, pk0);
		pkRing.put(1, pk1);
		pkRing.put(2, pk2);
		pkRing.put(3, pk3);
		
		if (PaillierPublicKeyRing.keyDir.toFile().exists())
		{
			if (PaillierPublicKeyRing.keyRingFile.toFile().exists())
			{
				PaillierPublicKeyRing.keyRingFile.toFile().delete();
			}
		}
		PaillierPublicKeyRing.keyDir.toFile().delete();
	}
	
	@Test
	public void testKeyStorageAndRetrieval()
	{
		Assert.assertEquals(4, pkRing.size());
		Assert.assertEquals(pk0, pkRing.get(0));
		Assert.assertEquals(pk1, pkRing.get(1));
		Assert.assertEquals(pk2, pkRing.get(2));
		Assert.assertEquals(pk3, pkRing.get(3));
	}
	
	@Test
	public void testPersistentStorage() throws Exception
	{
		pkRing.writeToFile();
		
		PaillierPublicKeyRing pkRing2 = PaillierPublicKeyRing.loadFromFile();
		
		Assert.assertEquals(pkRing, pkRing2);
	}
	
	@Test
	public void testEmptyRing()
	{
		PaillierPublicKeyRing pkRing = new PaillierPublicKeyRing();
		
		Assert.assertNull(pkRing.get(1));
		
		try
		{
			pkRing.writeToFile();
		}
		catch (IOException e)
		{
			fail("Failed to write to " + PaillierPublicKeyRing.keyRingFile);
		}
		File file = PaillierPublicKeyRing.keyRingFile.toFile();
		
		Assert.assertEquals(2, file.length());
		
		try
		{
			PaillierPublicKeyRing pkRing2 = PaillierPublicKeyRing.loadFromFile();
			Assert.assertEquals(pkRing, pkRing2);
		}
		catch (IOException e) { fail("Failed to read from " + PaillierPublicKeyRing.keyRingFile); }
		catch (ParseException e) { fail("Invalid json in " + PaillierPublicKeyRing.keyRingFile); }
	}
	
	@Test
	public void testMalformedJSON() throws IOException
	{
		if (!PaillierPublicKeyRing.keyDir.toFile().exists())
		{
			PaillierPublicKeyRing.keyDir.toFile().mkdir();
		}
		FileOutputStream fos = new FileOutputStream(PaillierPublicKeyRing.keyRingFile.toFile());
		
		fos.write("This is some malformed JSON }".getBytes());
		fos.close();
		
		try
		{
			PaillierPublicKeyRing pkRing = PaillierPublicKeyRing.loadFromFile();
			fail("Should have thrown a ParseException");
		}
		catch (ParseException e)
		{
			Assert.assertTrue(e.toString().equals("Unexpected character (T) at position 0."));
		}
	}
}
