package com.tudelft.paillier;

import com.tudelft.paillier.util.KeyRingUtil;
import com.tudelft.paillier.util.SerialisationUtil;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.tuple.Triple;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jetbrains.annotations.Nullable;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;

class PaillierPrivateKeyRing
{
	private static final Path keyRingFile  = Paths.get("./keys/sk_ring.pai");
	private static final Path AESKeyFile   = Paths.get("./keys/key.pai");
	private static final Path passHashFile = Paths.get("./keys/pass_hash.pai");
	private static final int  iterations   = 100000;
	private static final int  PBEKeyLength = 256;
	
	private transient Map<Integer, PaillierPrivateKey> keyRing;
	private transient String                           hashKey;
	private           boolean                          filesExist;
	
	PaillierPrivateKeyRing(String password) throws NoSuchAlgorithmException, InvalidKeySpecException
	{
		keyRing = new HashMap<>();
		filesExist = false;
		
		byte[]           salt = KeyRingUtil.genSalt();
		SecretKeyFactory skf  = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		PBEKeySpec       spec = new PBEKeySpec(password.toCharArray(), salt, iterations, PBEKeyLength);
		
		hashKey = iterations
				+ ":" + KeyRingUtil.toHex(salt)
				+ ":" + KeyRingUtil.toHex(skf.generateSecret(spec).getEncoded());
	}
	
	private PaillierPrivateKeyRing(JSONObject jsonObj, String hashKey)
	{
		this.keyRing = new HashMap<>();
		this.hashKey = hashKey;
		this.filesExist = true;
		
		for (Object userId : jsonObj.keySet())
		{
			PaillierPrivateKey sk = SerialisationUtil.unserialise_private((Map) jsonObj.get(userId));
			
			keyRing.put(Integer.parseInt((String) userId), sk);
		}
	}
	
	static PaillierPrivateKeyRing loadFromFile(String password) throws Exception
	{
		Security.addProvider(new BouncyCastleProvider());
		
		String hashKey = validatePassword(password);
		
		if (hashKey == null)
		{
			throw new Exception("Invalid password");
		}
		byte[]        AESKey     = loadAESKey(ArrayUtils.toPrimitive(KeyRingUtil.hashToTriple(hashKey).getRight()));
		byte[]        bytes      = Files.readAllBytes(keyRingFile);
		byte[]        iv         = ArrayUtils.subarray(bytes, 0, 16);
		byte[]        keyRingEnc = ArrayUtils.subarray(bytes, 16, bytes.length);
		JSONParser    parser     = new JSONParser();
		SecretKeySpec AESKeySpec = new SecretKeySpec(AESKey, "AES");
		Cipher        cipher     = Cipher.getInstance("AES/CBC/PKCS7Padding");
		
		cipher.init(Cipher.DECRYPT_MODE, AESKeySpec, new IvParameterSpec(iv));
		
		String     keyRingStr = new String(cipher.doFinal(keyRingEnc));
		JSONObject jsonObj    = (JSONObject) parser.parse(keyRingStr);
		
		return new PaillierPrivateKeyRing(jsonObj, hashKey);
	}
	
	void WriteToFile() throws Exception
	{
		Security.addProvider(new BouncyCastleProvider());
		
		if (!filesExist)
		{
			File dir = new File("./keys");
			
			if (!dir.exists())
			{
				dir.mkdir();
			}
			generateKey();
			generateHash();
		}
		if (!AESKeyFile.toFile().exists())
		{
			throw new FileNotFoundException("AES key file (" + AESKeyFile + ") not found, keyring file is unrecoverable.");
		}
		else if (!passHashFile.toFile().exists())
		{
			throw new FileNotFoundException(
					"password hash file (" + passHashFile + ") not found, keyring file is unrecoverable.");
		}
		JSONObject jsonObj = new JSONObject();
		
		for (Map.Entry id_key : keyRing.entrySet())
		{
			PrivateKeyJsonSerializer serializer = new PrivateKeyJsonSerializer("");
			
			((PaillierPrivateKey) id_key.getValue()).serialize(serializer);
			jsonObj.put(id_key.getKey(), serializer.getNode());
		}
		byte[]           key        = loadAESKey(ArrayUtils.toPrimitive(KeyRingUtil.hashToTriple(hashKey).getRight()));
		byte[]           iv         = KeyRingUtil.genSalt();
		SecretKeySpec    AESKeySpec = new SecretKeySpec(key, "AES");
		Cipher           cipher     = Cipher.getInstance("AES/CBC/PKCS7Padding");
		FileOutputStream fos        = new FileOutputStream(keyRingFile.toFile());
		
		cipher.init(Cipher.ENCRYPT_MODE, AESKeySpec, new IvParameterSpec(iv));
		fos.write(iv);
		fos.write(cipher.doFinal(jsonObj.toJSONString().getBytes()));
	}
	
	void put(int userId, PaillierPrivateKey sk) throws Exception
	{
		if (keyRing.containsKey(userId) && !keyRing.get(userId).equals(sk))
		{
			throw new Exception("There already exists a different private key for user ID " + userId + " in the keyring");
		}
		keyRing.put(userId, sk);
	}
	
	PaillierPrivateKey get(int userId) throws Exception
	{
		if (!keyRing.containsKey(userId))
		{
			throw new Exception("There exists no private key for user ID " + userId + " in the keyring");
		}
		return keyRing.get(userId);
	}
	
	private static byte[] loadAESKey(byte[] hashKey) throws Exception
	{
		byte[]        bytes      = Files.readAllBytes(AESKeyFile);
		byte[]        iv         = ArrayUtils.subarray(bytes, 0, 16);
		byte[]        keyEnc     = ArrayUtils.subarray(bytes, 16, bytes.length);
		SecretKeySpec AESKeySpec = new SecretKeySpec(hashKey, "AES");
		Cipher        cipher     = Cipher.getInstance("AES/CBC/PKCS7Padding");
		
		cipher.init(Cipher.DECRYPT_MODE, AESKeySpec, new IvParameterSpec(iv));
		
		return cipher.doFinal(keyEnc);
	}
	
	private void generateKey() throws Exception
	{
		byte[]        AESKey     = KeyRingUtil.genKey();
		byte[]        iv         = KeyRingUtil.genSalt();
		Triple        hashTriple = KeyRingUtil.hashToTriple(hashKey);
		SecretKeySpec AESKeySpec = new SecretKeySpec(ArrayUtils.toPrimitive((Byte[]) hashTriple.getRight()), "AES");
		Cipher        cipher     = Cipher.getInstance("AES/CBC/PKCS7Padding");
		
		cipher.init(Cipher.ENCRYPT_MODE, AESKeySpec);
		AESKeyFile.toFile().createNewFile();
		
		byte[]           AESKeyEnc = ArrayUtils.addAll(iv, cipher.doFinal(AESKey));
		FileOutputStream fos       = new FileOutputStream(AESKeyFile.toFile());
		
		fos.write(AESKeyEnc);
		fos.close();
	}
	
	private void generateHash() throws Exception
	{
		Triple           hashTriple  = KeyRingUtil.hashToTriple(hashKey);
		int              iterations  = (int) hashTriple.getLeft();
		byte[]           salt        = ArrayUtils.toPrimitive((Byte[]) hashTriple.getMiddle());
		String           hash        = KeyRingUtil.toHex(ArrayUtils.toPrimitive((Byte[]) hashTriple.getRight()));
		PBEKeySpec       spec        = new PBEKeySpec(hash.toCharArray(), salt, iterations, PBEKeyLength);
		SecretKeyFactory skf         = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		byte[]           passHash    = skf.generateSecret(spec).getEncoded();
		String           passHashStr = iterations + ":" + KeyRingUtil.toHex(salt) + ":" + KeyRingUtil.toHex(passHash);
		
		passHashFile.toFile().createNewFile();
		
		FileOutputStream fos = new FileOutputStream(passHashFile.toFile());
		
		fos.write(passHashStr.getBytes());
		fos.close();
	}
	
	@Nullable
	private static String validatePassword(String password) throws Exception
	{
		Triple           hashTriple = KeyRingUtil.loadStoredHash(passHashFile);  //<iterations, salt, hash>
		int              iterations = (int) hashTriple.getLeft();
		byte[]           salt       = ArrayUtils.toPrimitive((Byte[]) hashTriple.getMiddle());
		byte[]           storedHash = ArrayUtils.toPrimitive((Byte[]) hashTriple.getRight());
		SecretKeyFactory skf        = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		PBEKeySpec       firstSpec  = new PBEKeySpec(password.toCharArray(), salt, iterations, PBEKeyLength);
		String           firstHash  = KeyRingUtil.toHex(skf.generateSecret(firstSpec).getEncoded());
		PBEKeySpec       secondSpec = new PBEKeySpec(firstHash.toCharArray(), salt, iterations, PBEKeyLength);
		byte[]           secondHash = skf.generateSecret(secondSpec).getEncoded();
		int              diff       = storedHash.length ^ secondHash.length;
		
		for (int i = 0; i < storedHash.length && i < secondHash.length; i++)
		{
			diff |= storedHash[i] ^ secondHash[i];
		}
		return diff == 0
		       ? iterations + ":" + KeyRingUtil.toHex(salt) + ":" + firstHash
		       : null;
	}
}