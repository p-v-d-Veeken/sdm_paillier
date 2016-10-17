package com.tudelft.paillier;

import com.tudelft.paillier.util.SerialisationUtil;
import org.jetbrains.annotations.Nullable;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

public class PaillierPublicKeyRing
{
	public static final Path keyDir = Paths.get("./keys");
	public static final Path keyRingFile = Paths.get(keyDir + "/pk_ring.pai");
	
	private transient Map<Integer, PaillierPublicKey> keyRing;
	
	public PaillierPublicKeyRing()
	{
		keyRing = new HashMap<>();
	}
	
	private PaillierPublicKeyRing(JSONObject jsonObj)
	{
		keyRing = new HashMap<>();
		
		for (Object userId : jsonObj.keySet())
		{
			PaillierPublicKey pk = SerialisationUtil.unserialise_public((Map) jsonObj.get(userId));
			
			keyRing.put(Integer.parseInt((String) userId), pk);
		}
	}
	
	public static PaillierPublicKeyRing loadFromFile() throws IOException, ParseException
	{
		if(!keyDir.toFile().exists())
		{
			return new PaillierPublicKeyRing(new JSONObject());
		}
		JSONParser parser  = new JSONParser();
		JSONObject jsonObj = (JSONObject) parser.parse(new FileReader(keyRingFile.toFile()));
		
		return new PaillierPublicKeyRing(jsonObj);
	}
	
	public void writeToFile() throws IOException
	{
		if(!keyDir.toFile().exists())
		{
			if (!keyDir.toFile().mkdir())
			{
				throw new IOException("Could not create directory: " + keyDir);
			}
		}
		JSONObject jsonObj = new JSONObject();
		
		for (Map.Entry id_key : keyRing.entrySet())
		{
			PublicKeyJsonSerializer serializer = new PublicKeyJsonSerializer("");
			
			((PaillierPublicKey) id_key.getValue()).serialize(serializer);
			jsonObj.put(id_key.getKey(), serializer.getNode());
		}
		FileOutputStream fos = new FileOutputStream(keyRingFile.toFile());
		
		fos.write(jsonObj.toJSONString().getBytes());
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
	
	public int size()
	{
		return keyRing.size();
	}
	
	public boolean equals(Object o)
	{
		if (o == this) { return true; }
		if (o == null) { return false; }
		if(o.getClass() != PaillierPublicKeyRing.class) { return false; }
		
		PaillierPublicKeyRing other = (PaillierPublicKeyRing) o;
		
		for (Map.Entry id_key : keyRing.entrySet())
		{
			try
			{
				if (!other.get((Integer) id_key.getKey()).equals(id_key.getValue())) { return false; }
			}
			catch (Exception e) { return false; }
		}
		return true;
	}
}