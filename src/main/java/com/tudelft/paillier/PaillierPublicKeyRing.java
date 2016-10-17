package com.tudelft.paillier;

import com.tudelft.paillier.PaillierPublicKey;
import com.tudelft.paillier.cli.SerialisationUtil;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

class PaillierPublicKeyRing
{
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
	
	static PaillierPublicKeyRing loadFromFile(File file) throws IOException, ParseException
	{
		JSONParser parser  = new JSONParser();
		JSONObject jsonObj = (JSONObject) parser.parse(new FileReader(file));
		
		return new PaillierPublicKeyRing(jsonObj);
	}
	
	void put(int userId, PaillierPublicKey pk) throws Exception
	{
		if (keyRing.containsKey(userId) && !keyRing.get(userId).equals(pk))
		{
			throw new Exception("There already exists a different public key for user ID " + userId + " in the keyring");
		}
		keyRing.put(userId, pk);
	}
	
	PaillierPublicKey get(int userId) throws Exception
	{
		if (!keyRing.containsKey(userId))
		{
			throw new Exception("There exists no public key for user ID " + userId + "in the keyring");
		}
		return keyRing.get(userId);
	}
	
	void writeToFile(File file) throws IOException
	{
		JSONObject jsonObj = new JSONObject();
		
		for (Map.Entry id_key : keyRing.entrySet())
		{
			PublicKeyJsonSerializer serializer = new PublicKeyJsonSerializer("");
			
			((PaillierPublicKey) id_key.getValue()).serialize(serializer);
			jsonObj.put(id_key.getKey(), serializer.getNode());
		}
		FileOutputStream fos = new FileOutputStream(file);
		
		fos.write(jsonObj.toJSONString().getBytes());
		fos.close();
	}
}