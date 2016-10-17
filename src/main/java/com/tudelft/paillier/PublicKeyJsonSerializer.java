package com.tudelft.paillier;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.tudelft.paillier.PaillierPublicKey;
import org.apache.commons.codec.binary.Base64;

import java.math.BigInteger;

public class PublicKeyJsonSerializer implements PaillierPublicKey.Serializer
{
	// container object node
	private ObjectNode   data;
	private ObjectMapper mapper;
	private String       comment;
	
	PublicKeyJsonSerializer(String comment)
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
	public void serialize(BigInteger modulus)
	{
		data = mapper.createObjectNode();
		data.put("alg", "PAI-GN1");
		data.put("kty", "DAJ");
		data.put("kid", comment);
		
		// Convert n to base64 encode
		String encodedModulus = new String(Base64.encodeBase64(modulus.toByteArray()));
		data.put("n", encodedModulus);
		
		ArrayNode an = data.putArray("key_ops");
		an.add("encrypt");
	}
}