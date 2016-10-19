package com.tudelft.comparison;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

class Generator
{
	final static Random random = new SecureRandom();

	static BigInteger randName()
	{
		String name = "";

		for(int i = 0; i < Config.nameLength; i++)
		{
			char c = (char) (random.nextInt(26) + 'a');
			name += c;
		}
		return new BigInteger(name.getBytes());
	}
	static BigInteger randAge()
	{
		int age = random.nextInt(Config.ageMax - Config.ageMin + 1) + Config.ageMin;

		return BigInteger.valueOf(age);
	}
	static BigInteger randIncome()
	{
		int income = random.nextInt(Config.incomeMax - Config.incomeMin + 1) + Config.incomeMin;

		return BigInteger.valueOf(income);
	}
}