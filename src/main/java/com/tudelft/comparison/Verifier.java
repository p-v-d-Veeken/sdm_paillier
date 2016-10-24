package com.tudelft.comparison;

import com.tudelft.paillier.*;

import java.math.BigInteger;

class Verifier
{
	private transient PaillierPrivateKey sk;
	private transient PaillierContext    cxt;
	
	Verifier(PaillierPrivateKey sk)
	{
		this.sk = sk;
		this.cxt = sk.getPublicKey().createSignedContext();
	}
	
	/**
	 * Decrypts the randomized values and evaluates which is bigger.
	 * The evaluation result is then encrypted again and returned
	 *
	 * @param ar the randomized value a
	 * @param br the randomized value a
	 * @return [-1, 0, 1]
	 */
	EncryptedNumber getZ(EncryptedNumber ar, EncryptedNumber br)
	{
		BigInteger a = ar.decrypt(sk).decodeBigInteger();
		BigInteger b = br.decrypt(sk).decodeBigInteger();
		
		return cxt.encrypt(BigInteger.valueOf(a.compareTo(b)));
	}
}