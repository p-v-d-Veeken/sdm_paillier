package com.tudelft.comparison;

import com.tudelft.paillier.*;

import java.math.BigInteger;
import java.util.Vector;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

class Verifier
{
	private transient PaillierPrivateKey sk;
	private transient PaillierPublicKey  pk;
	private transient PaillierContext    cxt;
	public transient BigInteger         d1; //todo:: fix me
	
	Verifier(PaillierPrivateKey sk)
	{
		this.sk = sk;
		this.pk = sk.getPublicKey();
		this.cxt = pk.createSignedContext();
	}
	
	/**
	 * Return a modulus calculated value based on D.
	 * @param dEnc the d-component in the Paillier comparison scheme.
	 * @param l the maximum bit length of the two encrypted values
	 * @return [d2] = floor(d / 2^l)
	 */
	BigInteger getD2(BigInteger dEnc, int l)
	{
		BigInteger d  = sk.raw_decrypt(dEnc);
		BigInteger d1 = d.mod(BigInteger.valueOf(2).pow(l));     //d1 <= d mod 2^l
		BigInteger d2 = d.divide(BigInteger.valueOf(2).pow(l));  //d2 <= floor(d / 2^l)
		
		this.d1 = d1;
		
		return cxt.encrypt(d2).getCipherText();
	}
	
	/**
	 * Return the length of a bitshifted analysis list.
	 *
	 * @param l the maximum bit length of the two encrypted values
	 * @return [t_i] = d^1_i + sum^{l-1}_{j=i+1} 2^j * d^1_j
	 */
	Vector<BigInteger> getT(int l)
	{
		byte d1Bits = d1.byteValue();
		
		return IntStream.range(0, l)
				.parallel()
				.mapToObj(i ->
				{
					BigInteger ti = BigInteger.ZERO.add(BigInteger.valueOf((d1Bits >> i) & 1)); //t_i = d^1_i
					
					for (int j = i + 1; j < l; j++)
					{
						ti = ti.add(BigInteger.valueOf(2).pow(j) //t_i += sum^{l-1}_{j=i+1} 2^j * d^1_j
								.multiply(BigInteger.valueOf((d1Bits >> j) & 1))
						);
					}
					return cxt.encrypt(ti.mod(pk.getModulus())).getCipherText();
				})
				.collect(Collectors.toCollection(Vector<BigInteger>::new));
	}
	
	/**
	 * Evaluate the list [e] to verify if any of the values is 0.
	 *
	 * @param e The encrypted list of evaluation elements to be passed on to the verifier.
	 * @return if any e_i = 0 [A] = 1 otherwise [A] = 0
	 */
	BigInteger getA(Vector<BigInteger> e)
	{
		for (BigInteger ei_enc : e)
		{
			BigInteger ei = sk.raw_decrypt(ei_enc);
			
			if (ei.equals(BigInteger.ZERO))
			{
				return cxt.encrypt(BigInteger.ONE).getCipherText();
			}
		}
		return cxt.encrypt(BigInteger.ZERO).getCipherText();
	}
}