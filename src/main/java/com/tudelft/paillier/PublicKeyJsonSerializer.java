package com.tudelft.paillier;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.tudelft.paillier.util.SerialisationUtil;
import org.apache.commons.codec.binary.Base64;

import java.math.BigInteger;

public class PublicKeyJsonSerializer implements PaillierPublicKey.Serializer
{
	// container object node
	private JsonObject data;
	
	public JsonObject getNode()
	{
		return data;
	}
	
	@Override
	public String toString()
	{
		return data.toString();
	}
	
	@Override
	public void serialize(BigInteger modulus)
	{
		data = new JsonObject();
		data.add("alg", SerialisationUtil.gson.toJsonTree("PAI-GN1"));
		data.add("kty", SerialisationUtil.gson.toJsonTree("DAJ"));
		
		// Convert n to base64 encode
		String encodedModulus = new String(Base64.encodeBase64(modulus.toByteArray()));
		data.add("n", SerialisationUtil.gson.toJsonTree(encodedModulus));
		
		JsonArray an = new JsonArray();
		an.add("encrypt");
		data.add("key_ops", an);
	}
}