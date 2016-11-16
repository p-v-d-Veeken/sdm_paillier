package com.tudelft.paillier;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.tudelft.paillier.util.KeyRingUtil;
import com.tudelft.paillier.util.SerialisationUtil;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.tuple.Triple;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jetbrains.annotations.Nullable;

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
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

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
	
	public PaillierPrivateKeyRing(String password)
	{
		keyRing = new HashMap<>();
		filesExist = false;
		hashKey = hashFromPassword(password);
	}
	
	public PaillierPrivateKeyRing(String keyRingJsonStr, String password)
	{
		JsonParser             parser      = new JsonParser();
		JsonObject             keyRingJson = parser.parse(keyRingJsonStr).getAsJsonObject();
		String                 hashKey     = password != null ? hashFromPassword(password) : null;
		PaillierPrivateKeyRing that        = new PaillierPrivateKeyRing(keyRingJson, hashKey);
		
		this.keyRing = that.keyRing;
		this.hashKey = that.hashKey;
		this.filesExist = false;
	}
	
	private PaillierPrivateKeyRing(JsonObject keyRingJson, String hashKey)
	{
		this.keyRing = new HashMap<>();
		this.hashKey = hashKey;
		this.filesExist = true;
		
		for (Map.Entry<String, JsonElement> entry : keyRingJson.entrySet())
		{
			PaillierPrivateKey sk = SerialisationUtil.unserialise_private((JsonObject) entry.getValue());
			
			keyRing.put(Integer.parseInt(entry.getKey()), sk);
		}
	}
	
	public static PaillierPrivateKeyRing loadFromFile(String password) throws IOException
	{
		Security.addProvider(new BouncyCastleProvider());
		
		String hashKey = validatePassword(password);
		
		if (hashKey == null)
		{
			throw new PaillierKeyMismatchException("Invalid passphrase, could not decrypt keyring.");
		}
		try
		{
			byte[]        AESKey     = loadAESKey(ArrayUtils.toPrimitive(KeyRingUtil.hashToTriple(hashKey).getRight()));
			byte[]        bytes      = Files.readAllBytes(keyRingFile);
			byte[]        iv         = ArrayUtils.subarray(bytes, 0, 16);
			byte[]        keyRingEnc = ArrayUtils.subarray(bytes, 16, bytes.length);
			JsonParser    parser     = new JsonParser();
			SecretKeySpec AESKeySpec = new SecretKeySpec(AESKey, "AES");
			Cipher        cipher     = Cipher.getInstance("AES/CBC/PKCS7Padding");
			
			cipher.init(Cipher.DECRYPT_MODE, AESKeySpec, new IvParameterSpec(iv));
			
			String     keyRingStr  = new String(cipher.doFinal(keyRingEnc));
			JsonObject keyRingJson = (JsonObject) parser.parse(keyRingStr);
			
			return new PaillierPrivateKeyRing(keyRingJson, hashKey);
		}
		catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException |
				InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) { e.printStackTrace(); }
		
		throw new PaillierRuntimeException("Could not load keyring from file.");
	}
	
	public void writeToFile() throws IOException, PaillierKeyMismatchException
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
		try
		{
			JsonObject       keyRingJson = serializeKeyRing();
			byte[]           key         = loadAESKey(ArrayUtils.toPrimitive(KeyRingUtil.hashToTriple(hashKey).getRight()));
			byte[]           iv          = KeyRingUtil.genSalt();
			SecretKeySpec    AESKeySpec  = new SecretKeySpec(key, "AES");
			Cipher           cipher      = Cipher.getInstance("AES/CBC/PKCS7Padding");
			FileOutputStream fos         = new FileOutputStream(keyRingFile.toFile());
			
			cipher.init(Cipher.ENCRYPT_MODE, AESKeySpec, new IvParameterSpec(iv));
			fos.write(iv);
			fos.write(cipher.doFinal(keyRingJson.toString().getBytes()));
		}
		catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException |
				InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) { e.printStackTrace(); }
	}
	
	public void put(int userId, PaillierPrivateKey sk)
	{
		keyRing.put(userId, sk);
	}
	
	public PaillierPrivateKey get(int userId)
	{
		return keyRing.get(userId);
	}
	
	public List<Integer> keys()
	{
		return keyRing.keySet()
				.stream()
				.collect(Collectors.toList());
	}
	
	public int size()
	{
		return keyRing.size();
	}
	
	private static byte[] loadAESKey(byte[] hashKey)
			throws IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
	{
		byte[]        bytes      = Files.readAllBytes(AESKeyFile);
		byte[]        iv         = ArrayUtils.subarray(bytes, 0, 16);
		byte[]        keyEnc     = ArrayUtils.subarray(bytes, 16, bytes.length);
		SecretKeySpec AESKeySpec = new SecretKeySpec(hashKey, "AES");
		
		try
		{
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
			cipher.init(Cipher.DECRYPT_MODE, AESKeySpec, new IvParameterSpec(iv));
			
			return cipher.doFinal(keyEnc);
		}
		catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException e)
		{
			e.printStackTrace();
		}
		throw new PaillierRuntimeException("Could not load keyring AES key.");
	}
	
	private JsonObject serializeKeyRing()
	{
		JsonObject keyRingJson = new JsonObject();
		
		for (Map.Entry<Integer, PaillierPrivateKey> id_key : keyRing.entrySet())
		{
			PrivateKeyJsonSerializer serializer = new PrivateKeyJsonSerializer();
			
			id_key.getValue().serialize(serializer);
			keyRingJson.add(id_key.getKey().toString(), serializer.getNode());
		}
		return keyRingJson;
	}
	
	private String hashFromPassword(String password)
	{
		try
		{
			byte[]           salt = KeyRingUtil.genSalt();
			SecretKeyFactory skf  = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
			PBEKeySpec       spec = new PBEKeySpec(password.toCharArray(), salt, iterations, PBEKeyLength);
			
			return iterations
					+ ":" + KeyRingUtil.toHex(salt)
					+ ":" + KeyRingUtil.toHex(skf.generateSecret(spec).getEncoded());
		}
		catch (NoSuchAlgorithmException | InvalidKeySpecException e) { e.printStackTrace(); }
		
		throw new PaillierRuntimeException("Could not generate password hash.");
	}
	
	private void generateKeyFile() throws IOException
	{
		byte[]        AESKey     = KeyRingUtil.genKey();
		byte[]        iv         = KeyRingUtil.genSalt();
		Triple        hashTriple = KeyRingUtil.hashToTriple(hashKey);
		SecretKeySpec AESKeySpec = new SecretKeySpec(ArrayUtils.toPrimitive((Byte[]) hashTriple.getRight()), "AES");
		
		try
		{
			Cipher           cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
			FileOutputStream fos    = new FileOutputStream(AESKeyFile.toFile());
			
			cipher.init(Cipher.ENCRYPT_MODE, AESKeySpec);
			AESKeyFile.toFile().createNewFile();
			
			byte[] AESKeyEnc = ArrayUtils.addAll(iv, cipher.doFinal(AESKey));
			fos.write(AESKeyEnc);
			fos.close();
		}
		catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException |
				BadPaddingException e) { e.printStackTrace(); }
	}
	
	private void generateHashFile() throws IOException, PaillierKeyMismatchException
	{
		if (hashKey == null)
		{
			throw new PaillierKeyMismatchException("No password specified; keyring can not be encrypted.");
		}
		
		Triple     hashTriple = KeyRingUtil.hashToTriple(hashKey);
		int        iterations = (int) hashTriple.getLeft();
		byte[]     salt       = ArrayUtils.toPrimitive((Byte[]) hashTriple.getMiddle());
		String     hash       = KeyRingUtil.toHex(ArrayUtils.toPrimitive((Byte[]) hashTriple.getRight()));
		PBEKeySpec spec       = new PBEKeySpec(hash.toCharArray(), salt, iterations, PBEKeyLength);
		
		try
		{
			SecretKeyFactory skf      = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
			byte[]           passHash = skf.generateSecret(spec).getEncoded();
			
			String passHashStr = iterations + ":" + KeyRingUtil.toHex(salt) + ":" + KeyRingUtil.toHex(passHash);
			
			passHashFile.toFile().createNewFile();
			
			FileOutputStream fos = new FileOutputStream(passHashFile.toFile());
			
			fos.write(passHashStr.getBytes());
			fos.close();
		}
		catch (NoSuchAlgorithmException | InvalidKeySpecException e) { e.printStackTrace(); }
	}
	
	@Nullable
	private static String validatePassword(String password) throws IOException
	{
		Triple hashTriple = KeyRingUtil.loadStoredHash(passHashFile);  //<iterations, salt, hash>
		int    iterations = (int) hashTriple.getLeft();
		byte[] salt       = ArrayUtils.toPrimitive((Byte[]) hashTriple.getMiddle());
		byte[] storedHash = ArrayUtils.toPrimitive((Byte[]) hashTriple.getRight());
		
		try
		{
			SecretKeyFactory skf        = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
			PBEKeySpec       firstSpec  = new PBEKeySpec(password.toCharArray(), salt, iterations, PBEKeyLength);
			String           firstHash  = KeyRingUtil.toHex(skf.generateSecret(firstSpec).getEncoded());
			PBEKeySpec       secondSpec = new PBEKeySpec(firstHash.toCharArray(), salt, iterations, PBEKeyLength);
			byte[]           secondHash = skf.generateSecret(secondSpec).getEncoded();
			
			int diff = storedHash.length ^ secondHash.length;
			
			for (int i = 0; i < storedHash.length && i < secondHash.length; i++)
			{
				diff |= storedHash[i] ^ secondHash[i];
			}
			return diff == 0
			       ? iterations + ":" + KeyRingUtil.toHex(salt) + ":" + firstHash
			       : null;
		}
		catch (NoSuchAlgorithmException | InvalidKeySpecException e) { e.printStackTrace(); }
		
		throw new PaillierRuntimeException("Could not validate password.");
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