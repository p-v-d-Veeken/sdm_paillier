package com.tudelft.paillier;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.tudelft.paillier.util.SerialisationUtil;
import org.jetbrains.annotations.Nullable;

import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class PaillierPublicKeyRing
{
	public static final Path keyDir      = Paths.get("./keys");
	public static final Path keyRingFile = Paths.get(keyDir + "/pk_ring.pai");
	
	private transient Map<Integer, PaillierPublicKey> keyRing;
	
	public PaillierPublicKeyRing()
	{
		keyRing = new HashMap<>();
	}
	
	public PaillierPublicKeyRing(String keyRingJsonStr)
	{
		PaillierPublicKeyRing that = new PaillierPublicKeyRing((JsonObject) new JsonParser().parse(keyRingJsonStr));
		
		this.keyRing = that.keyRing;
	}
	
	private PaillierPublicKeyRing(JsonObject keyRingJson)
	{
		keyRing = new HashMap<>();
		
		for (Map.Entry<String, JsonElement> entry : keyRingJson.entrySet())
		{
			PaillierPublicKey pk = SerialisationUtil.unserialise_public((JsonObject) entry.getValue());
			
			keyRing.put(Integer.parseInt(entry.getKey()), pk);
		}
	}
	
	public static PaillierPublicKeyRing loadFromFile() throws IOException
	{
		if (!keyDir.toFile().exists())
		{
			throw new IOException("Directory: " + keyDir + " does not exist.");
		}
		JsonParser parser      = new JsonParser();
		JsonObject keyRingJson = (JsonObject) parser.parse(new FileReader(keyRingFile.toFile()));
		
		return new PaillierPublicKeyRing(keyRingJson);
	}
	
	public void writeToFile() throws IOException
	{
		if (!keyDir.toFile().exists())
		{
			if (!keyDir.toFile().mkdir())
			{
				throw new IOException("Could not create directory: " + keyDir + ".");
			}
		}
		JsonObject keyRingJson = new JsonObject();
		
		for (Map.Entry<Integer, PaillierPublicKey> id_key : keyRing.entrySet())
		{
			PublicKeyJsonSerializer serializer = new PublicKeyJsonSerializer();
			
			id_key.getValue().serialize(serializer);
			keyRingJson.add(id_key.getKey().toString(), serializer.getNode());
		}
		FileOutputStream fos = new FileOutputStream(keyRingFile.toFile());
		
		fos.write(keyRingJson.toString().getBytes());
		fos.close();
	}
	
	public void put(int userId, PaillierPublicKey pk)
	{
		keyRing.put(userId, pk);
	}
	
	@Nullable
	public PaillierPublicKey get(int userId)
	{
		return keyRing.get(userId);
	}
	
	public List<Integer> keys()
	{
		return keyRing.keySet()
				.stream()
				.collect(Collectors.toList());
	}
	
	public int size()
	{
		return keyRing.size();
	}
	
	public boolean equals(Object o)
	{
		if (o == this) { return true; }
		if (o == null) { return false; }
		if (o.getClass() != PaillierPublicKeyRing.class) { return false; }
		
		PaillierPublicKeyRing other = (PaillierPublicKeyRing) o;
		
		for (Map.Entry id_key : keyRing.entrySet())
		{
			if (!id_key.getValue().equals(other.get((Integer) id_key.getKey()))) { return false; }
		}
		return true;
	}
}