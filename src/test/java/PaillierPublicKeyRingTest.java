import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import com.tudelft.paillier.PaillierPrivateKey;
import com.tudelft.paillier.PaillierPublicKey;
import com.tudelft.paillier.PaillierPublicKeyRing;
import com.tudelft.paillier.PublicKeyJsonSerializer;
import org.junit.Assert;
import org.junit.Test;

import java.io.File;
import java.io.IOException;

import static junit.framework.TestCase.fail;
import static org.hamcrest.CoreMatchers.is;

@SuppressWarnings("Duplicates")
public class PaillierPublicKeyRingTest
{
	private PaillierPublicKeyRing pkRing;
	private PaillierPublicKey     pk0;
	private JsonObject            pk0Serialized;
	private PaillierPublicKey     pk1;
	private PaillierPublicKey     pk2;
	private PaillierPublicKey     pk3;
	
	public PaillierPublicKeyRingTest() throws Exception
	{
		PublicKeyJsonSerializer pk0Serializer = new PublicKeyJsonSerializer();
		JsonParser              parser        = new JsonParser();
		
		pkRing = new PaillierPublicKeyRing();
		pk0 = PaillierPrivateKey.create(1024).getPublicKey();
		pk0.serialize(pk0Serializer);
		pk0Serialized = (JsonObject) parser.parse(pk0Serializer.toString());
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
	public void testFromJson() throws Exception
	{
		String                jsonStr = "{\"0\":" + pk0Serialized.toString() + "}";
		PaillierPublicKeyRing pkRing  = new PaillierPublicKeyRing(jsonStr);
		
		Assert.assertThat("Private keys should be identical", pkRing.get(0), is(pk0));
	}
	
	@Test
	public void testMalformedJson() throws IOException
	{
		String jsonStr = "This is some malformed Json }";
		
		try
		{
			PaillierPublicKeyRing pkRing = new PaillierPublicKeyRing(jsonStr);
			fail("Should have thrown a ParseException");
		}
		catch (JsonSyntaxException e)
		{
			Assert.assertEquals(e.getClass().toString(), "class com.google.gson.JsonSyntaxException");
		}
	}
}