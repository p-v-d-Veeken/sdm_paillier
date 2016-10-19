package com.tudelft.paillier;

import com.tudelft.paillier.util.KeyRingUtil;

import java.io.File;
import java.io.FileOutputStream;
import java.math.BigInteger;

public class Main
{
	public static void main(String[] args) throws Exception
	{
		/*PaillierPublicKeyRing  pkRing = PaillierPublicKeyRing.loadFromFile();
		
		byte[] encryptedPhrase = pkRing.get(0).createSignedContext()
				.encode(new BigInteger("North Korea best Korea".getBytes()))
				.encrypt()
				.getCipherText()
				.toByteArray();*/
		
		File file = new File("test.pai");
		file.createNewFile();
		FileOutputStream fos = new FileOutputStream(file);
		fos.write(KeyRingUtil.toHex(new BigInteger("165165165682238").toByteArray()).getBytes());
		fos.close();
	}
}
