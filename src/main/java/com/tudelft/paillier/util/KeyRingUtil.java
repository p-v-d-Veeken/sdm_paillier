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
	
	public static Triple<Integer, Byte[], Byte[]> loadStoredHash(Path passHashFile) throws IOException
	{
		String hashStr = Files.lines(passHashFile).reduce("", (p, line) -> p + line);
		
		return hashToTriple(hashStr);
	}
	
	public static Triple<Integer, Byte[], Byte[]> hashToTriple(String hashStr)
	{
		String[] parts      = hashStr.split(":");
		Integer  iterations = Integer.parseInt(parts[0]);
		Byte[]   salt       = ArrayUtils.toObject(fromHex(parts[1]));
		Byte[]   hash       = ArrayUtils.toObject(fromHex(parts[2]));
		
		return Triple.of(iterations, salt, hash);
	}
	
	public static byte[] fromHex(String hex)
	{
		byte[] bytes = new byte[hex.length() / 2];
		for (int i = 0; i < bytes.length; i++)
		{
			bytes[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
		}
		return bytes;
	}
	
	public static String toHex(byte[] array)
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
		return randBytes(16);
	}
	
	public static byte[] genKey()
	{
		return randBytes(256 / 8);
	}
	
	public static byte[] randBytes(int amount)
	{
		byte[] bytes = new byte[amount];
		
		random.nextBytes(bytes);
		
		return bytes;
	}
}