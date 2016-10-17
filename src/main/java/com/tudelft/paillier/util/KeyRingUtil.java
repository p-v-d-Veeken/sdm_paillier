package com.tudelft.paillier.util;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.tuple.Triple;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class KeyRingUtil
{
	private static final SecureRandom random = new SecureRandom();
	
	public static Triple<Integer, Byte[], Byte[]> loadStoredHash(Path passHashFile) throws IOException, NoSuchAlgorithmException
	{
		String hashStr = Files.lines(passHashFile).reduce("", (p, line) -> p + line);
		
		return hashToTriple(hashStr);
	}
	
	public static Triple<Integer, Byte[], Byte[]> hashToTriple(String hashStr) throws IOException, NoSuchAlgorithmException
	{
		String[] parts      = hashStr.split(":");
		Integer  iterations = Integer.parseInt(parts[0]);
		Byte[]   salt       = ArrayUtils.toObject(fromHex(parts[1]));
		Byte[]   hash       = ArrayUtils.toObject(fromHex(parts[2]));
		
		return Triple.of(iterations, salt, hash);
	}
	
	public static byte[] fromHex(String hex) throws NoSuchAlgorithmException
	{
		byte[] bytes = new byte[hex.length() / 2];
		for (int i = 0; i < bytes.length; i++)
		{
			bytes[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
		}
		return bytes;
	}
	
	public static String toHex(byte[] array) throws NoSuchAlgorithmException
	{
		BigInteger bi            = new BigInteger(1, array);
		String     hex           = bi.toString(16);
		int        paddingLength = (array.length * 2) - hex.length();
		
		if (paddingLength > 0)
		{
			return String.format("%0" + paddingLength + "d", 0) + hex;
		}
		else
		{
			return hex;
		}
	}
	
	public static byte[] genSalt()
	{
		byte[] salt = new byte[16];
		
		random.nextBytes(salt);
		
		return salt;
	}
	
	public static byte[] genKey()
	{
		byte[] key   = new byte[256 / 8];
		
		random.nextBytes(key);
		
		return key;
	}
}