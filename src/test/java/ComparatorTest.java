import com.tudelft.comparison.ComparisonValuesVerifier;
import com.tudelft.paillier.PaillierContext;
import com.tudelft.paillier.PaillierPrivateKey;
import com.tudelft.paillier.PaillierPrivateKeyRing;
import com.tudelft.paillier.PaillierPublicKey;
import com.tudelft.comparison.Comparator;

import static org.junit.Assert.*;
import static org.hamcrest.CoreMatchers.*;

import org.apache.commons.lang3.tuple.Pair;
import org.junit.Test;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

@SuppressWarnings("Duplicates")
public class ComparatorTest
{
	private PaillierPrivateKey sk;
	private PaillierPublicKey  pk;
	private PaillierContext    cxt;
	private Random             rand;
	
	public ComparatorTest() throws Exception
	{
		PaillierPrivateKeyRing skRing = PaillierPrivateKeyRing.loadFromFile("test");
		
		sk = skRing.get(0);
		pk = sk.getPublicKey();
		cxt = pk.createSignedContext();
		rand = new Random(105100);
	}
	
	@Test
	public void compareTestALessThanB() throws Exception
	{
		Comparator comp = new Comparator(pk, sk, false);
		
		rand.ints(5, 1, 101).forEach(num ->
		{
			BigInteger a   = BigInteger.valueOf(1 + rand.nextInt(num));
			BigInteger b   = BigInteger.valueOf(num);
			int        l   = Integer.max(a.bitLength(), b.bitLength());
			BigInteger res = comp.compare(cxt.encrypt(a).getCipherText(), cxt.encrypt(b).getCipherText(), l);
			
			assertThat("Should be " + a + " <= " + b + ", was " + a + " > " + b, sk.raw_decrypt(res), is(BigInteger.ZERO));
		});
	}
	
	@Test
	public void compareTestAGreaterThanB() throws Exception
	{
		Comparator comp = new Comparator(pk, sk, false);
		
		rand.ints(5, 1, 101).forEach(num ->
		{
			BigInteger a   = BigInteger.valueOf(num);
			BigInteger b   = BigInteger.valueOf(1 + rand.nextInt(num));
			int        l   = Integer.max(a.bitLength(), b.bitLength());
			BigInteger res = comp.compare(cxt.encrypt(a).getCipherText(), cxt.encrypt(b).getCipherText(), l);
			
			assertThat("Should be " + a + " > " + b + ", was " + a + " <= " + b, sk.raw_decrypt(res), is(BigInteger.ONE));
		});
	}
	
	/*@Test
	public void compareTestAEqualsThanB() throws Exception
	{
		Comparator               comp = new Comparator(pk, sk, false);
		BigInteger               a    = BigInteger.valueOf(429);
		BigInteger               b    = BigInteger.valueOf(429);
		int                      l    = Integer.max(a.bitLength(), b.bitLength());
		BigInteger               res  = comp.compare(cxt.encrypt(a).getCipherText(), cxt.encrypt(b).getCipherText(), l);
		//ComparisonValuesVerifier veri = new ComparisonValuesVerifier(comp.getValues(), sk);
		
		//veri.verifyValues();
		
		assertThat("Should be " + a + " <= " + b + ", was " + a + " > " + b, sk.raw_decrypt(res), is(BigInteger.ZERO));
	}*/
}
