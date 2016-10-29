package com.tudelft.paillier;

import com.tudelft.paillier.util.KeyRingUtil;
import com.tudelft.paillier.util.SerialisationUtil;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.tuple.Triple;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jetbrains.annotations.Nullable;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;

public class PaillierPrivateKeyRing
{
	public static Path keyDir       = Paths.get("./keys");
	public static Path keyRingFile  = Paths.get(keyDir + "/sk_ring.pai");
	public static Path AESKeyFile   = Paths.get(keyDir + "/key.pai");
	public static Path passHashFile = Paths.get(keyDir + "/pass_hash.pai");
	public static int  iterations   = 100000;
	public static int  PBEKeyLength = 256;
	
	private transient Map<Integer, PaillierPrivateKey> keyRing;
	private transient String                           hashKey;
	private           boolean                          filesExist;
	
	public PaillierPrivateKeyRing(String password) throws NoSuchAlgorithmException, InvalidKeySpecException
	{
		keyRing = new HashMap<>();
		filesExist = false;
		hashKey = hashFromPassword(password);
	}
	
	public PaillierPrivateKeyRing(String keyRingJsonStr, String password)
			throws ParseException, NoSuchAlgorithmException, InvalidKeySpecException
	{
		JSONObject             keyRingJson = (JSONObject) new JSONParser().parse(keyRingJsonStr);
		String                 hashKey     = password != null ? hashFromPassword(password) : null;
		PaillierPrivateKeyRing that        = new PaillierPrivateKeyRing(keyRingJson, hashKey);
		
		this.keyRing = that.keyRing;
		this.hashKey = that.hashKey;
		this.filesExist = false;
	}
	
	private PaillierPrivateKeyRing(JSONObject keyRingJson, String hashKey)
	{
		this.keyRing = new HashMap<>();
		this.hashKey = hashKey;
		this.filesExist = true;
		
		for (Object userId : keyRingJson.keySet())
		{
			PaillierPrivateKey sk = SerialisationUtil.unserialise_private((Map) keyRingJson.get(userId));
			
			keyRing.put(Integer.parseInt((String) userId), sk);
		}
	}
	
	public static PaillierPrivateKeyRing loadFromFile(String password)
			throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, IllegalBlockSizeException,
			       InvalidKeyException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException,
			       ParseException
	{
		Security.addProvider(new BouncyCastleProvider());
		
		String hashKey = validatePassword(password);
		
		if (hashKey == null)
		{
			throw new PaillierKeyMismatchException("Invalid passphrase, could not decrypt keyring.");
		}
		byte[]        AESKey     = loadAESKey(ArrayUtils.toPrimitive(KeyRingUtil.hashToTriple(hashKey).getRight()));
		byte[]        bytes      = Files.readAllBytes(keyRingFile);
		byte[]        iv         = ArrayUtils.subarray(bytes, 0, 16);
		byte[]        keyRingEnc = ArrayUtils.subarray(bytes, 16, bytes.length);
		JSONParser    parser     = new JSONParser();
		SecretKeySpec AESKeySpec = new SecretKeySpec(AESKey, "AES");
		Cipher        cipher     = Cipher.getInstance("AES/CBC/PKCS7Padding");
		
		cipher.init(Cipher.DECRYPT_MODE, AESKeySpec, new IvParameterSpec(iv));
		
		String     keyRingStr  = new String(cipher.doFinal(keyRingEnc));
		JSONObject keyRingJson = (JSONObject) parser.parse(keyRingStr);
		
		return new PaillierPrivateKeyRing(keyRingJson, hashKey);
	}
	
	public void writeToFile()
			throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			       InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException,
			       InvalidKeySpecException
	{
		Security.addProvider(new BouncyCastleProvider());
		
		if (!filesExist)
		{
			File dir = new File("./keys");
			
			if (!dir.exists())
			{
				dir.mkdir();
			}
			generateHashFile();
			generateKeyFile();
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
		JSONObject       keyRingJson = serializeKeyRing();
		byte[]           key         = loadAESKey(ArrayUtils.toPrimitive(KeyRingUtil.hashToTriple(hashKey).getRight()));
		byte[]           iv          = KeyRingUtil.genSalt();
		SecretKeySpec    AESKeySpec  = new SecretKeySpec(key, "AES");
		Cipher           cipher      = Cipher.getInstance("AES/CBC/PKCS7Padding");
		FileOutputStream fos         = new FileOutputStream(keyRingFile.toFile());
		
		cipher.init(Cipher.ENCRYPT_MODE, AESKeySpec, new IvParameterSpec(iv));
		fos.write(iv);
		fos.write(cipher.doFinal(keyRingJson.toJSONString().getBytes()));
	}
	
	public void put(int userId, PaillierPrivateKey sk)
	{
		keyRing.put(userId, sk);
	}
	
	public PaillierPrivateKey get(int userId)
	{
		return keyRing.get(userId);
	}
	
	public int size()
	{
		return keyRing.size();
	}
	
	private static byte[] loadAESKey(byte[] hashKey)
			throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			       InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
	{
		byte[]        bytes      = Files.readAllBytes(AESKeyFile);
		byte[]        iv         = ArrayUtils.subarray(bytes, 0, 16);
		byte[]        keyEnc     = ArrayUtils.subarray(bytes, 16, bytes.length);
		SecretKeySpec AESKeySpec = new SecretKeySpec(hashKey, "AES");
		Cipher        cipher     = Cipher.getInstance("AES/CBC/PKCS7Padding");
		
		cipher.init(Cipher.DECRYPT_MODE, AESKeySpec, new IvParameterSpec(iv));
		
		return cipher.doFinal(keyEnc);
	}
	
	private JSONObject serializeKeyRing()
	{
		JSONObject keyRingJson = new JSONObject();
		
		for (Map.Entry id_key : keyRing.entrySet())
		{
			PrivateKeyJsonSerializer serializer = new PrivateKeyJsonSerializer("");
			
			((PaillierPrivateKey) id_key.getValue()).serialize(serializer);
			keyRingJson.put(id_key.getKey(), serializer.getNode());
		}
		return keyRingJson;
	}
	
	private String hashFromPassword(String password) throws NoSuchAlgorithmException, InvalidKeySpecException
	{
		byte[]           salt = KeyRingUtil.genSalt();
		SecretKeyFactory skf  = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		PBEKeySpec       spec = new PBEKeySpec(password.toCharArray(), salt, iterations, PBEKeyLength);
		
		return iterations
				+ ":" + KeyRingUtil.toHex(salt)
				+ ":" + KeyRingUtil.toHex(skf.generateSecret(spec).getEncoded());
	}
	
	private void generateKeyFile()
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
			       IOException, BadPaddingException, IllegalBlockSizeException
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
	
	private void generateHashFile()
			throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException
	{
		if (hashKey == null) { throw new InvalidKeyException("No password specified; keyring can not be encrypted."); }
		
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
	private static String validatePassword(String password)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException
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
	
	public boolean equals(Object o)
	{
		if (o == this) { return true; }
		if (o == null) { return false; }
		if (o.getClass() != PaillierPrivateKeyRing.class) { return false; }
		
		PaillierPrivateKeyRing that       = (PaillierPrivateKeyRing) o;
		Triple                 thisTriple = KeyRingUtil.hashToTriple(hashKey);
		Triple                 thatTriple = KeyRingUtil.hashToTriple(that.hashKey);
		
		if (!thisTriple.getLeft().equals(thatTriple.getLeft())) { return false; }
		if (thisTriple.getRight() == thatTriple.getRight()) { return false; }
		
		for (Map.Entry id_key : keyRing.entrySet())
		{
			if (!id_key.getValue().equals(that.get((Integer) id_key.getKey()))) { return false; }
		}
		return true;
	}
}