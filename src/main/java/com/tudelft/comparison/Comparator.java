package com.tudelft.comparison;

import com.tudelft.paillier.*;
import com.tudelft.paillier.util.BigIntegerUtil;
import org.apache.commons.lang3.tuple.Triple;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Vector;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class Comparator
{
	public static final int MAX_BIT_LENGTH = 90;
	
	private transient PaillierPublicKey   pk;
	private transient PaillierContext     cxt;
	private transient Verifier            verifier;
	private           boolean             debug;
	private           Map<String, Object> values;
	
	public Comparator(PaillierPublicKey pk, PaillierPrivateKey sk, boolean debug)
	{
		this.pk = pk;
		this.cxt = pk.createSignedContext();
		this.verifier = new Verifier(sk);
		this.debug = debug;
	}
	
	/**
	 * Securely compare two values encrypted wth the Paillier crypto system
	 *
	 * @param a, encrypted
	 * @param b, encrypted
	 * @param l  the maximum bit length of the two encrypted values
	 */
	public BigInteger compare(BigInteger a, BigInteger b, int l)
	{
		if(l > MAX_BIT_LENGTH)
		{
			throw new PaillierRuntimeException("Maximum bit length exceeded, max: " + MAX_BIT_LENGTH + ", was: " + l);
		}
		BigInteger         z  = calculateZ(a, b, l);    //[z] = [2^l] * [a] * [b]^-1
		BigInteger         r  = calculateR(l);          //r = random int of 80 + l + 1 bits
		BigInteger         d  = calculateD(z, r);       //[d] = [z] * [r]
		BigInteger         d2 = verifier.getD2(d, l);   //[d^1] = d mod 2^l; [d^2] = floor(d / 2^l)
		Vector<BigInteger> t  = verifier.getT(l);       //[t_i] = d^1_i + sum^{l-1}_{j=i+1} 2^j * d^1_j
		BigInteger         s  = BigIntegerUtil.random.nextBoolean() ? BigInteger.ONE : BigInteger.valueOf(-1);
		Vector<BigInteger> h  = calculateH(l);          //h_0,..., h_{l-1} = rand int in Z*_N
		Vector<BigInteger> v  = calculateV(r, s, l);    //[v_i] = s - r_i - sum^{l - 1}_{j = i + 1} 2^j * r_j
		Vector<BigInteger> e  = calculateE(v, t, h, l); //[e_i] = [v_i] * [t_i] ^ h_i
		BigInteger         A  = verifier.getA(e);       //if any e_i = 0 [A] = 1 otherwise [A] = 0
		BigInteger         zl = calculateZl(d2, r, s, A, l);
		
		if (debug)
		{
			fillValues(a, b, z, BigInteger.valueOf(l), r, s, d, d2, t, h, v, e, A, zl);
		}
		return zl;
	}
	
	public BigInteger compare(BigInteger a, BigInteger b)
	{
		return compare(a, b, MAX_BIT_LENGTH);
	}
	
	private void fillValues(
			BigInteger a, BigInteger b, BigInteger z, BigInteger l, BigInteger r, BigInteger s, BigInteger d,
			BigInteger d2, Vector<BigInteger> t, Vector<BigInteger> h, Vector<BigInteger> v, Vector<BigInteger> e,
			BigInteger A, BigInteger zl)
	{
		values = new HashMap<>();
		//values.put("a", a);
		//values.put("b", b);
		//values.put("l", l);
		values.put("z", z);
		//values.put("r", r);
		//values.put("s", s);
		values.put("d", d);
		//values.put("d1", verifier.d1);
		values.put("d2", d2);
		values.put("t", t);
		values.put("h", h);
		values.put("v", v);
		values.put("e", e);
		values.put("A", A);
		values.put("zl", zl);
	}
	
	public Map<String, Object> getValues()
	{
		return values;
	}
	
	/**
	 * Calculate the z-component in the Paillier comparison scheme.
	 *
	 * @param a, encrypted
	 * @param b, encrypted
	 * @param l  the maximum bit length of the two encrypted values
	 * @return [z] = [2 ^ l] * [a] * [b] ^ -1
	 */
	private BigInteger calculateZ(BigInteger a, BigInteger b, int l)
	{
		return pk.alt_encrypt(BigInteger.valueOf(2).pow(l))//[z] <= [2^l] * [a] * [b]^-1
				.multiply(a)
				.mod(pk.getModulusSquared())
				.multiply(b.modInverse(pk.getModulusSquared()))
				.mod(pk.getModulusSquared());
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
	
	/**
	 * Calculate the d-component in the Paillier comparison scheme.
	 *
	 * @param z component of the Paillier comparison Scheme
	 * @param r random int of 80 + l + 1 bits
	 * @return [d] = [z].[r]
	 */
	private BigInteger calculateD(BigInteger z, BigInteger r)
	{
		return z.multiply(pk.alt_encrypt(r))
				.mod(pk.getModulusSquared());
	}
	
	/**
	 * Generate a random list
	 *
	 * @param l the maximum bit length of the two encrypted values
	 * @return h_0, ..., h_{l-1} = rand int in Z*_N
	 */
	private Vector<BigInteger> calculateH(int l)
	{
		return IntStream.range(0, l)
				.mapToObj(hi -> pk.randomZStarN())
				.collect(Collectors.toCollection(Vector<BigInteger>::new));
	}
	
	/**
	 * Generate a differential list based on the bit values of r and s as basis.
	 *
	 * @param l the maximum bit length of the two encrypted values
	 * @param r random int of 80 + l + 1 bits
	 * @param s randomly chosen from [-1, 1]
	 * @return [v_i] = s - r_i - sum^{l - 1}_{j = i + 1} 2^j * r_j
	 */
	private Vector<BigInteger> calculateV(BigInteger r, BigInteger s, int l)
	{
		byte rBits = r.byteValue();
		
		return IntStream.range(0, l)
				.parallel()
				.mapToObj(i ->
				{
					BigInteger vi = s.subtract(BigInteger.valueOf((rBits >> i) & 1)); //v_i = s - r_i
					
					for (int j = i + 1; j < l; j++)
					{
						vi = vi.subtract(BigInteger.valueOf(2).pow(j) //v_i += sum^{l-1}_{j=i+1} 2^j * r_j
								.multiply(BigInteger.valueOf((rBits >> j) & 1))
						);
					}
					return pk.raw_encrypt(vi.mod(pk.getModulus()));
				})
				.collect(Collectors.toCollection(Vector<BigInteger>::new));
	}
	
	/**
	 * Encrypted list of evaluation elements to be passed on to the verifier.
	 *
	 * @param v = list of v_i = s - r_i - sum^{l - 1}_{j = i + 1} 2^j * r_j
	 * @param t = list of t_i = d^1_i + sum^{l-1}_{j=i+1} 2^j * d^1_j
	 * @param h = list of h_0,..., h_{l-1} = rand int in Z*_N
	 * @param l the maximum bit length of the two encrypted values
	 * @return [e_i] = [v_i] * [t_i] ^ h_i
	 */
	private Vector<BigInteger> calculateE(Vector<BigInteger> v, Vector<BigInteger> t, Vector<BigInteger> h, int l)
	{
		return IntStream.range(0, l)
				.parallel()
				.mapToObj(i -> Triple.of(v.get(i), t.get(i), h.get(i)))
				.map(vth ->
				{ //vth = {v_i, t_i, h_i}
					BigInteger ci = vth.getLeft()
							.multiply(vth.getMiddle())
							.mod(pk.getModulusSquared());
					
					return ci.modPow(vth.getRight(), pk.getModulusSquared());
				}).collect(Collectors.toCollection(Vector<BigInteger>::new));
	}
	
	/**
	 * Evaluate the returned statement from the verifier and calculate the result of the comparison.
	 *
	 * @param d2 = floor(d / 2^l)
	 * @param r  random int of 80 + l + 1 bits
	 * @param s  randomly chosen from [-1, 1]
	 * @param A  = lambda = if s == i then [A] otherwise [A] = [1] * [A] ^-1
	 * @param l  the maximum bit length of the two encrypted values
	 * @return [zl] = [d^2] * [floor(r / 2^l)]^ -1 * [A]^-1
	 */
	private BigInteger calculateZl(BigInteger d2, BigInteger r, BigInteger s, BigInteger A, int l)
	{
		if (!s.equals(BigInteger.ONE))
		{
			A = cxt.encrypt(BigInteger.ONE).getCipherText()
					.multiply(A.modInverse(pk.getModulusSquared()))
					.mod(pk.getModulusSquared());
		}
		BigInteger r2l = cxt.encrypt(r.divide(BigInteger.valueOf(2).pow(l))).getCipherText();
		
		return d2
				.multiply(r2l.modInverse(pk.getModulusSquared()))
				.mod(pk.getModulusSquared())
				.multiply(A.modInverse(pk.getModulusSquared()))
				.mod(pk.getModulusSquared());
	}
}