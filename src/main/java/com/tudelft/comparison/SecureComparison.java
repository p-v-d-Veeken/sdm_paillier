package com.tudelft.comparison;

import com.tudelft.paillier.*;

import java.math.BigInteger;
import java.util.Vector;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class SecureComparison
{
	private transient PaillierPrivateKey sk;
	private transient PaillierPublicKey  pk;
	private transient PaillierContext    cxt;
	private transient Verifier           verifier;
	
	public SecureComparison(PaillierPublicKey pk, PaillierPrivateKey sk)
	{
		this.pk = pk;
		this.sk = sk;
		this.cxt = pk.createSignedContext();
		this.verifier = new Verifier(sk);
	}
	
	public BigInteger compare(BigInteger a, BigInteger b, int l) throws Exception
	{
		BigInteger         z  = calculateZ(a, b, l);//[z] = [2^l] * [a] * [b]^-1
		BigInteger         r  = calculateR(l);      //r = random int of 80 + l + 1 bits
		BigInteger         d  = calculateD(z, r);   //[d] = [z] * [r]
		BigInteger         d2 = verifier.getD2(d, l);//[d^1] = d mod 2^l; [d^2] = floor(d / 2^l)
		Vector<BigInteger> t  = verifier.getT(l);   //[t_i] = d^1_i + sum^{l-1}_{j=i+1} 2^j * d^1_j
		BigInteger         s  = BigInteger.ONE.negate();
		Vector<BigInteger> h  = calculateH(l);      //h_0,..., h_{l-1} = rand int in Z*_N
		Vector<BigInteger> v  = calculateV(s, r, l);//[v_i] = s - r_i - sum^{l - 1}_{j = i + 1} 2^j * r_j
		BigInteger         A  = calculateA(v, t, s, h, l);
		
		return calculateZl(d2, r, A, l);
	}
	
	private BigInteger calculateZ(BigInteger a, BigInteger b, int l) throws Exception
	{
		return cxt.encode(BigInteger.valueOf(2).pow(l))//[z] <= [2^l] * [a] * [b]^-1
				.encrypt()
				.getCipherText()
				.multiply(a)
				.mod(pk.getModulusSquared())
				.multiply(b.modInverse(pk.getModulusSquared()))
				.mod(pk.getModulusSquared());
	}
	
	private BigInteger calculateR(int l)
	{
		return new BigInteger(80 + l + 1, Generator.random); //r = random int of 80 + l + 1 bits
	}
	
	private BigInteger calculateD(BigInteger z, BigInteger r) throws Exception
	{
		return z.multiply(cxt.encode(r).encrypt().getCipherText())
				.mod(pk.getModulusSquared());
	}
	
	private Vector<BigInteger> calculateH(int l)
	{
		Vector<BigInteger> h = new Vector<>(l);
		
		for (int i = 0; i < l; i++)
		{
			h.add(pk.randomZStarN());
		}
		return h; // h_0,..., h_{l-1} = rand int in Z*_N
	}
	
	private Vector<BigInteger> calculateV(BigInteger s, BigInteger r, int l) throws Exception
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
								.multiply(BigInteger.valueOf((rBits >> j) & 1)).mod(pk.getModulus())
						);
					}
					return cxt.encrypt(vi.mod(pk.getModulus())).getCipherText();
				})
				.collect(Collectors.toCollection(Vector<BigInteger>::new));
	}
	
	private BigInteger calculateA(
			Vector<BigInteger> v, Vector<BigInteger> t, BigInteger s, Vector<BigInteger> h, int l) throws Exception
	{
		BigInteger A = BigInteger.ONE.negate();
		
		IntStream.range(1, l)
				.mapToObj(i -> new BigInteger[]{v.get(i), t.get(i), h.get(i)})
				.parallel()
				.map(vth ->
				{ //vth = {v_i, t_i, h_i}
					try
					{
						BigInteger ci = vth[0]
								.multiply(vth[1])
								.mod(pk.getModulusSquared());
						BigInteger ei = ci.modPow(vth[2], pk.getModulusSquared());
						
						return verifier.getA(ei);
					}
					catch (Exception e) { e.printStackTrace(); }
					return A;
				})
				.reduce(A, (pv, cv) ->
				{
					if (cv.equals(BigInteger.ONE) || pv.equals(BigInteger.ONE))
					{
						return BigInteger.ONE;
					}
					return cv;
				});
		return !s.equals(BigInteger.ONE)                            //If s != 1
		       ? cxt.encrypt(BigInteger.ONE)                    //Then [A] = [1 - A]
				       .getCipherText()
				       .multiply(A.modInverse(pk.getModulusSquared()))
				       .mod(pk.getModulusSquared())
		       : A;                                                 //Else [A] = [A]
	}
	
	private BigInteger calculateZl(BigInteger d2, BigInteger r, BigInteger A, int l) throws Exception
	{
		BigInteger r2l = cxt.encrypt(r.divide(BigInteger.valueOf(2).pow(l))).getCipherText();
		
		return d2 //[zl] = [d2] * [floor(r / 2^l)]^-1 * [A]^-1
				.multiply(r2l.modInverse(pk.getModulusSquared()))
				.mod(pk.getModulusSquared())
				.multiply(A.modInverse(pk.getModulusSquared()))
				.mod(pk.getModulusSquared());
	}
}