package com.tudelft.paillier;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.tudelft.paillier.util.BigIntegerUtil;
import org.apache.commons.codec.binary.Base64;

import java.math.BigInteger;

public class PrivateKeyJsonSerializer implements PaillierPrivateKey.Serializer
{
	private ObjectNode   data;
	private ObjectMapper mapper;
	private String       comment;
	
	public PrivateKeyJsonSerializer(String comment)
	{
		mapper = new ObjectMapper();
		mapper.enable(SerializationFeature.INDENT_OUTPUT);
		this.comment = comment;
	}
	
	public ObjectNode getNode()
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
		data = mapper.createObjectNode();
		data.put("kty", "DAJ");
		ArrayNode an = data.putArray("key_ops");
		an.add("decrypt");
		
		PublicKeyJsonSerializer serialisedPublicKey = new PublicKeyJsonSerializer(comment);
		publickey.serialize(serialisedPublicKey);
		data.set("pub", serialisedPublicKey.getNode());
		
		
		data.put("kid", comment);
		
		BigInteger lambda        = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
		String     encodedLambda = new String(Base64.encodeBase64(lambda.toByteArray()));
		data.put("lambda", encodedLambda);
		
		BigInteger mu        = BigIntegerUtil.invert(lambda, publickey.getModulus());
		String     encodedMu = new String(Base64.encodeBase64(mu.toByteArray()));
		data.put("mu", encodedMu);
	}
}