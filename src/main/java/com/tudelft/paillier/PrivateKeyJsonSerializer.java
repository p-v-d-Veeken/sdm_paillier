package com.tudelft.paillier;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.tudelft.paillier.util.SerialisationUtil;
import org.apache.commons.codec.binary.Base64;

import java.math.BigInteger;

public class PrivateKeyJsonSerializer implements PaillierPrivateKey.Serializer
{
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
	public void serialize(PaillierPublicKey publickey, BigInteger p, BigInteger q)
	{
		data = new JsonObject();
		data.add("kty", SerialisationUtil.gson.toJsonTree("DAJ"));
		JsonArray an = new JsonArray();
		an.add("decrypt");
		data.add("key_ops", an);
		
		PublicKeyJsonSerializer serialisedPublicKey = new PublicKeyJsonSerializer();
		publickey.serialize(serialisedPublicKey);
		data.add("pub", serialisedPublicKey.getNode());
		
		BigInteger lambda        = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
		String     encodedLambda = new String(Base64.encodeBase64(lambda.toByteArray()));
		data.add("lambda", SerialisationUtil.gson.toJsonTree(encodedLambda));
	}
}