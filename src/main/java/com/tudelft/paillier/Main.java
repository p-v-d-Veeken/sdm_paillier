package com.tudelft.paillier;

import java.util.Random;
import java.util.stream.IntStream;

public class Main
{
	public static void main(String[] args) throws Exception
	{
		/*PaillierPrivateKey     sk     = PaillierPrivateKey.create(2048);
		PaillierPublicKey      pk     = sk.getPublicKey();
		PaillierPrivateKeyRing skRing = new PaillierPrivateKeyRing("test");
		PaillierPublicKeyRing  pkRing = new PaillierPublicKeyRing();
		
		skRing.put(0, sk);
		pkRing.put(0, pk);
		
		skRing.writeToFile();
		pkRing.writeToFile();*/
		
		Random rand = new Random(1234567891011121314L);
		int lo = 1;
		int hi = 100;
		
		IntStream.range(0, 20)
				.forEach(i -> {
						int a = lo + rand.nextInt(hi + 1);
						int b = lo + rand.nextInt(hi + 1);
					
					if(a > b)
					{
						System.out.println("(" + a + ", "+ b + ")");
					}
					else
					{
						System.out.println("(" + b + ", "+ a + ")");
					}
				});
	}
}
