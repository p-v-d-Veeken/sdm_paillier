import com.tudelft.paillier.PaillierContext;
import com.tudelft.paillier.PaillierPrivateKey;
import com.tudelft.paillier.PaillierPrivateKeyRing;
import com.tudelft.comparison.Comparator;

import static org.junit.Assert.*;
import static org.hamcrest.CoreMatchers.*;

import org.junit.Test;

import java.math.BigInteger;
import java.util.Random;

public class ComparatorTest
{
	private PaillierPrivateKey sk;
	private PaillierContext    cxt;
	private Random             rand;
	private int                test_iterations;
	private char[]             symbol;
	
	public ComparatorTest() throws Exception
	{
		PaillierPrivateKeyRing skRing = PaillierPrivateKeyRing.loadFromFile("test");
		
		sk = skRing.get(0);
		cxt = sk.getPublicKey().createSignedContext();
		rand = new Random(333333333333L);
		test_iterations = 20;
		symbol = new char[]{'<', '=', '>'};
	}
	
	private BigInteger randBigInteger(BigInteger upperBound)
	{
		BigInteger r;
		
		do
		{
			r = new BigInteger(upperBound.bitLength(), rand);
		}
		while (r.compareTo(upperBound) >= 0);
		
		return r;
	}
	
	@Test
	public void compareTestALessThanB()
	{
		Comparator comp = new Comparator(sk);
		
		for (int i = 0; i < test_iterations; i++)
		{
			BigInteger b   = new BigInteger(Comparator.MAX_BIT_LENGTH, 64, rand);
			BigInteger a   = randBigInteger(b);
			int        l   = Integer.max(a.bitLength(), b.bitLength());
			BigInteger res = sk.decrypt(comp.compare(cxt.encrypt(a), cxt.encrypt(b), l)).decodeBigInteger();
			
			assertThat("Should be " + a + " < " + b + ", was " + a + symbol[1 + res.intValue()] + b
					, res
					, is(BigInteger.ONE.negate()));
		}
	}
	
	@Test
	public void compareTestAGreaterThanB()
	{
		Comparator comp = new Comparator(sk);
		
		for (int i = 0; i < test_iterations; i++)
		{
			BigInteger a   = new BigInteger(Comparator.MAX_BIT_LENGTH, 64, rand);
			BigInteger b   = randBigInteger(a);
			int        l   = Integer.max(a.bitLength(), b.bitLength());
			BigInteger res = sk.decrypt(comp.compare(cxt.encrypt(a), cxt.encrypt(b), l)).decodeBigInteger();
			
			assertThat("Should be " + a + " > " + b + ", was " + a + symbol[1 + res.intValue()] + b
					, res
					, is(BigInteger.ONE));
		}
	}
	
	@Test
	public void compareTestAEqualsThanB()
	{
		Comparator comp = new Comparator(sk);
		
		for (int i = 0; i < test_iterations; i++)
		{
			BigInteger a   = new BigInteger(Comparator.MAX_BIT_LENGTH, 64, rand);
			BigInteger b   = a;
			int        l   = Integer.max(a.bitLength(), b.bitLength());
			BigInteger res = sk.decrypt(comp.compare(cxt.encrypt(a), cxt.encrypt(b), l)).decodeBigInteger();
			
			assertThat("Should be " + a + " < " + b + ", was " + a + symbol[1 + res.intValue()] + b
					, res
					, is(BigInteger.ZERO));
		}
	}
}
