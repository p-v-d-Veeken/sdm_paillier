package com.tudelft.comparison;

import com.tudelft.paillier.*;
import com.tudelft.paillier.util.BigIntegerUtil;

import java.math.BigInteger;

public class Comparator
{
	public static final int MAX_BIT_LENGTH = 90;
	
	private transient Verifier verifier;
	
	public Comparator(PaillierPrivateKey sk)
	{
		this.verifier = new Verifier(sk);
	}
	
	/**
	 * Securely compare two values encrypted wth the Paillier crypto system.
	 *
	 * @param a, encrypted
	 * @param b, encrypted
	 * @param l  the maximum bit length of the two encrypted values
	 */
	public EncryptedNumber compare(EncryptedNumber a, EncryptedNumber b, int l)
	{
		if (l > MAX_BIT_LENGTH)
		{
			throw new PaillierRuntimeException("Maximum bit length exceeded, max: " + MAX_BIT_LENGTH + ", was: " + l);
		}
		BigInteger r = calculateR(l);
		a = a.multiply(r);
		b = b.multiply(r);
		
		return verifier.getZ(a, b);
	}
	
	/**
	 * Securely compare two values encrypted wth the Paillier crypto system. If no bit length is specified,
	 * The maximum bit length is assumed.
	 *
	 * @param a, encrypted
	 * @param b, encrypted
	 */
	public EncryptedNumber compare(EncryptedNumber a, EncryptedNumber b)
	{
		return compare(a, b, MAX_BIT_LENGTH);
	}
	
	/**
	 * Calculate the r-component in the Paillier comparison scheme.
	 *
	 * @param l the maximum bit length of the two encrypted values
	 * @return random int of 80 + l + 1 bits
	 */
	private BigInteger calculateR(int l)
	{
		return new BigInteger(80 + l + 1, BigIntegerUtil.random); //r = random int of 80 + l + 1 bits
	}
}