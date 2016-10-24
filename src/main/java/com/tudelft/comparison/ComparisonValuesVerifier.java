package com.tudelft.comparison;

import com.tudelft.paillier.PaillierPrivateKey;
import com.tudelft.paillier.util.BigIntegerUtil;
import org.apache.commons.lang3.tuple.Triple;

import java.math.BigInteger;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class ComparisonValuesVerifier
{
	private Map<String, Object> decrypted;
	private PaillierPrivateKey  sk;
	private Paillier            paillier;
	
	public ComparisonValuesVerifier(Map<String, Object> values, PaillierPrivateKey sk)
	{
		this.paillier = new Paillier(sk);
		this.sk = sk;
		
		List<String> listKeys  = Arrays.asList("t", "h", "v", "e");
		List<String> unEncKeys = Arrays.asList("d1", "h", "l", "r", "s");
		
		decrypted = values.entrySet()
				.stream()
				.map(entry ->
				{
					Object decryptedVal;
					
					if (!listKeys.contains(entry.getKey()))
					{
						decryptedVal = !unEncKeys.contains(entry.getKey())
						               ? decrypt((BigInteger) entry.getValue())
						               : entry.getValue();
					}
					else
					{
						decryptedVal = ((List<BigInteger>) entry.getValue()).stream()
								.map(val -> !unEncKeys.contains(entry.getKey())
								            ? decrypt((BigInteger) val)
								            : val)
								.collect(Collectors.toList());
					}
					return new AbstractMap.SimpleEntry<>(entry.getKey(), decryptedVal);
				}).collect(Collectors.toMap(p -> p.getKey(), p -> p.getValue()));
	}
	
	private BigInteger decrypt(BigInteger c)
	{
		try
		{
			return paillier.decrypt(c);
		}
		catch (Exception e)
		{
			e.printStackTrace();
		}
		return BigInteger.ZERO;
	}
	
	public boolean verifyValues() throws Exception
	{
		BigInteger         a  = (BigInteger) decrypted.get("a");
		BigInteger         b  = (BigInteger) decrypted.get("b");
		int                l  = ((BigInteger) decrypted.get("l")).intValue();
		BigInteger         z  = (BigInteger) decrypted.get("z");
		BigInteger         r  = (BigInteger) decrypted.get("r");
		BigInteger         s  = (BigInteger) decrypted.get("s");
		BigInteger         d  = (BigInteger) decrypted.get("d");
		BigInteger         d1 = (BigInteger) decrypted.get("d1");
		BigInteger         d2 = (BigInteger) decrypted.get("d2");
		List<BigInteger> v  = (List<BigInteger>) decrypted.get("v");
		List<BigInteger> t  = (List<BigInteger>) decrypted.get("t");
		List<BigInteger> h  = (List<BigInteger>) decrypted.get("h");
		List<BigInteger> e  = (List<BigInteger>) decrypted.get("e");
		BigInteger         A  = (BigInteger) decrypted.get("A");
		
		verifyZ(a, b, l);
		verifyD(z, r);
		verifyd2(d, l);
		verifyT(l, d1);
		verifyV(r, s, l);
		verifyE(v, t, h, l);
		verifyA(e);
		verifyZl(d2, r, s, A, l);
		
		return true;
	}
	
	private void verifyZ(BigInteger a, BigInteger b, int l) throws Exception
	{
		BigInteger zActual = (BigInteger) decrypted.get("z");
		BigInteger zExpect = BigInteger.valueOf(2).pow(l)
				.multiply(a)
				.divide(b);
		
		if (!zExpect.equals(zActual))
		{
			throw new Exception("Expected: z = 2^" + l +  " * " + a + " * " + b + " = " + zExpect +
					"\nbut was : z = " + zActual);
		}
	}
	
	private void verifyD(BigInteger z, BigInteger r) throws Exception
	{
		BigInteger dActual = (BigInteger) decrypted.get("d");
		BigInteger dExpect = z.multiply(r);
		
		if (!dExpect.equals(dActual))
		{
			throw new Exception("Expected: d = " + dExpect + "\nbut was : d = " + dActual);
		}
	}
	
	private void verifyd2(BigInteger d, int l) throws Exception
	{
		BigInteger d2Actual = (BigInteger) decrypted.get("d2");
		BigInteger d2Expect = decrypt(d).divide(BigInteger.valueOf(2).pow(l));
		
		if (!d2Expect.equals(d2Actual))
		{
			throw new Exception("Expected: d2 = " + d2Expect + "\nbut was : d2 = " + d2Actual);
		}
	}
	
	private void verifyT(int l, BigInteger d1) throws Exception
	{
		byte               d1Bits  = d1.byteValue();
		List<BigInteger> tActual = (List<BigInteger>) decrypted.get("t");
		List<BigInteger> tExpect = IntStream.range(0, l)
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
					return ti;
				})
				.collect(Collectors.toList());
		
		if (!tExpect.equals(tActual))
		{
			throw new Exception("Expected: T = " + tExpect + "\nbut was : T = " + tActual);
		}
	}
	
	private void verifyV(BigInteger r, BigInteger s, int l) throws Exception
	{
		byte               rBits   = r.byteValue();
		List<BigInteger> rActual = (List<BigInteger>) decrypted.get("r");
		List<BigInteger> rExpect = IntStream.range(0, l)
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
					return vi;
				})
				.collect(Collectors.toList());
		
		if (!rExpect.equals(rActual))
		{
			throw new Exception("Expected: V = " + rExpect + "\nbut was : V = " + rActual);
		}
	}
	
	private void verifyE(List<BigInteger> v, List<BigInteger> t, List<BigInteger> h, int l) throws Exception
	{
		List<BigInteger> eActual = (List<BigInteger>) decrypted.get("e");
		List<BigInteger> eExpect = IntStream.range(0, l)
				.parallel()
				.mapToObj(i -> Triple.of(v.get(i), t.get(i), h.get(i)))
				.map(vth ->
				{ //vth = {v_i, t_i, h_i}
					BigInteger ci = vth.getLeft()
							.multiply(vth.getMiddle());
					
					return ci.mod(vth.getRight());
				}).collect(Collectors.toList());
		
		if (!eExpect.equals(eActual))
		{
			throw new Exception("Expected: E = " + eExpect + "\nbut was : E = " + eActual);
		}
	}
	
	private void verifyA(List<BigInteger> e) throws Exception
	{
		BigInteger aActual = (BigInteger) decrypted.get("A");
		BigInteger aExpect = BigInteger.ZERO;
		
		for (BigInteger ei_enc : e)
		{
			BigInteger ei = decrypt(ei_enc);
			
			if (ei.equals(BigInteger.ZERO))
			{
				aActual = BigInteger.ONE;
			}
		}
		if (!aExpect.equals(aActual))
		{
			throw new Exception("Expected: A = " + aExpect + "\nbut was : A = " + aActual);
		}
	}
	
	private void verifyZl(BigInteger d2, BigInteger r, BigInteger s, BigInteger A, int l) throws Exception
	{
		BigInteger zlActual = (BigInteger) decrypted.get("zl");
		BigInteger zlExpect;
		
		if (!s.equals(BigInteger.ONE))
		{
			A = BigInteger.ONE.multiply(A.divide(A));
		}
		BigInteger r2l = r.divide(BigInteger.valueOf(2).pow(l));
		
		zlExpect = d2.divide(r2l).divide(A);
		
		if (!zlExpect.equals(zlActual))
		{
			throw new Exception("Expected: A = " + zlExpect + "\nbut was : A = " + zlActual);
		}
	}
}