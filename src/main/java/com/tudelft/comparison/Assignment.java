package com.tudelft.comparison;

import com.tudelft.paillier.*;

import java.math.BigInteger;
import java.util.Scanner;

class Assignment
{
	static void assignment1(Scanner scanner) throws Exception
	{
		System.out.print("Enter the desired database size:\n> ");
		
		int size = scanner.nextInt();
		
		System.out.println("Generating and encrypting database...");
		
		Database              db     = new Database(size);
		PaillierPublicKeyRing pkRing = PaillierPublicKeyRing.loadFromFile();
		PaillierPublicKey     pk     = pkRing.get(0);
		long                  tick   = System.currentTimeMillis();
		
		db.encryptDatabase(pk);
		
		long tock = System.currentTimeMillis();
		
		System.out.println(String.format("%1$d "
				+ (size == 1
				   ? "entry"
				   : "entries") +
				" encrypted in %2$d ms", size, tock - tick));
	}
	
	static void assignment2(Scanner scanner) throws Exception
	{
		PaillierPrivateKeyRing skRing = PaillierPrivateKeyRing.loadFromFile("test");
		PaillierPrivateKey     sk     = skRing.get(0);
		PaillierPublicKey      pk     = sk.getPublicKey();
		PaillierContext        cxt    = pk.createSignedContext();
		SecureComparison       comp   = new SecureComparison(pk, sk);
		BigInteger             a, b, res;
		long                   tick, tock;
		int                    l;
		String                 msg;
		
		System.out.print("Enter an integer value for a:\n> ");
		
		a = BigInteger.valueOf(scanner.nextInt());
		
		System.out.print("Enter an integer value for b:\n> ");
		
		b = BigInteger.valueOf(scanner.nextInt());
		l = Integer.max(a.bitLength(), b.bitLength());
		tick = System.currentTimeMillis();
		res = comp.compare(cxt.encrypt(a.mod(pk.getModulus())).getCipherText(), cxt.encrypt(b.mod(pk.getModulus())).getCipherText(), l);
		tock = System.currentTimeMillis();
		res = sk.raw_decrypt(res);
		msg = res.equals(BigInteger.ONE)
		      ? "Computed that a (%1$d) > b (%2$d) in %3$d ms"
		      : "Computed that a (%1$d) <= b (%2$d) in %3$d ms";
		
		System.out.println(String.format(msg, a, b, tock - tick));
	}
	
/*
	static void assignment3(Scanner scanner) throws Exception
	{
		System.out.print("Enter the desired database size:\n> ");
		
		int size = scanner.nextInt();
		
		System.out.println("Generating and encrypting database...");
		
		Database database = new Database(size);
		Paillier paillier = new Paillier(Config.modLength);
		
		database.encryptDatabase(paillier);
		System.out.print("Enter the desired age:\n> ");
		
		BigInteger age = BigInteger.valueOf(scanner.nextInt());
		
		System.out.println("Performing search to find people whose age is greater than " + age + "...");
		
		DatabaseQuery       query  = new DatabaseQuery(paillier, database);
		long                tick   = System.currentTimeMillis();
		List<DatabaseEntry> result = query.findGreaterThan(Config.column.AGE, paillier.encrypt(age), age.bitLength());
		long                tock   = System.currentTimeMillis();
		
		System.out.println("Found " + result.size() + " people older than " + age + " in " + (tock - tick) + " ms.");
		System.out.println("Computing total income of all found persons...");
		
		BigInteger income = BigInteger.ZERO;
		tick = System.currentTimeMillis();
		
		for (int i = 0; i < result.size(); i++)
		{
			BigInteger value = result.get(i).get(Config.column.INCOME);
			income = i == 0
			         ? value
			         : income
					         .multiply(value)
					         .mod(paillier.getNsquare());
		}
		income = paillier.decrypt(income);
		tock = System.currentTimeMillis();
		
		System.out.println(
				"Total income of the found people is " + income + ". Computation took " + (tock - tick) + " ms.");
	}
*/
}