package com.tudelft.paillier.util;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.tudelft.paillier.PaillierPrivateKey;
import com.tudelft.paillier.PaillierPublicKey;
import org.apache.commons.codec.binary.Base64;

import java.math.BigInteger;

/**
 * Class for common serialisation utils used in the CLI.
 */
public class SerialisationUtil
{
	
	public static final Gson gson = new Gson();
	
	public static PaillierPublicKey unserialise_public(JsonObject data)
	{
		// decode the modulus
		BigInteger n = new BigInteger(Base64.decodeBase64(data.get("n").getAsString()));
		
		return new PaillierPublicKey(n);
	}
	
	public static PaillierPrivateKey unserialise_private(JsonObject data)
	{
		// First step is to unserialise the Public key
		PaillierPublicKey pub    = unserialise_public((JsonObject) data.get("pub"));
		BigInteger        lambda = new BigInteger(Base64.decodeBase64(data.get("lambda").getAsString()));
		
		return new PaillierPrivateKey(pub, lambda);
	}
}
