import com.tudelft.paillier.PaillierContext;
import com.tudelft.paillier.PaillierPrivateKey;
import com.tudelft.paillier.PaillierPrivateKeyRing;
import com.tudelft.paillier.PaillierPublicKey;
import com.tudelft.comparison.SecureComparison;

import static org.junit.Assert.*;
import static org.hamcrest.CoreMatchers.*;

import org.junit.Test;

import java.math.BigInteger;

@SuppressWarnings("Duplicates")
public class SecureComparisonTest
{
	private PaillierPrivateKey sk;
	private PaillierPublicKey  pk;
	private PaillierContext    cxt;
	
	public SecureComparisonTest() throws Exception
	{
		PaillierPrivateKeyRing skRing = PaillierPrivateKeyRing.loadFromFile("test");
		
		sk = skRing.get(0);
		pk = sk.getPublicKey();
		cxt = pk.createSignedContext();
	}
	
	@Test
	public void compareTestALessThanB() throws Exception
	{
		SecureComparison comp = new SecureComparison(pk, sk);
		BigInteger       a    = BigInteger.valueOf(61);
		BigInteger       b    = BigInteger.valueOf(24);
		int              l    = Integer.compare(a.bitLength(), b.bitLength());
		BigInteger       res  = comp.compare(cxt.encrypt(a).getCipherText(), cxt.encrypt(b).getCipherText(), l);
		
		res = sk.raw_decrypt(res).compareTo(BigInteger.ONE) == 1
				? sk.raw_decrypt(res).subtract(pk.getModulus()).add(BigInteger.ONE)
		      : sk.raw_decrypt(res);
		
		assertThat("Should be A <= B, was A > B", (res), is(BigInteger.ZERO));
	}
	
	@Test
	public void compareTestAGreaterThanB() throws Exception
	{
		SecureComparison comp = new SecureComparison(pk, sk);
		BigInteger       a    = BigInteger.valueOf(353218924);
		BigInteger       b    = BigInteger.valueOf(35434250);
		int              l    = Integer.compare(a.bitLength(), b.bitLength());
		BigInteger       res  = comp.compare(cxt.encrypt(a).getCipherText(), cxt.encrypt(b).getCipherText(), l);
		
		res = sk.raw_decrypt(res).compareTo(BigInteger.ONE) == 1
				? sk.raw_decrypt(res).subtract(pk.getModulus()).add(BigInteger.ONE)
		      : sk.raw_decrypt(res);
		
		assertThat("Should be A > B, was A <= B", (res), is(BigInteger.ONE));
	}
	
	@Test
	public void compareTestAEqualsThanB() throws Exception
	{
		SecureComparison comp = new SecureComparison(pk, sk);
		BigInteger       a    = BigInteger.valueOf(429989908);
		BigInteger       b    = BigInteger.valueOf(429989908);
		int              l    = Integer.compare(a.bitLength(), b.bitLength());
		BigInteger       res  = comp.compare(cxt.encrypt(a).getCipherText(), cxt.encrypt(b).getCipherText(), l);
		
		res = sk.raw_decrypt(res).compareTo(BigInteger.ONE) == 1
				? sk.raw_decrypt(res).subtract(pk.getModulus()).add(BigInteger.ONE)
		      : sk.raw_decrypt(res);
		
		assertThat("Should be A <= B, was A > B", (res), is(BigInteger.ZERO));
	}
}
