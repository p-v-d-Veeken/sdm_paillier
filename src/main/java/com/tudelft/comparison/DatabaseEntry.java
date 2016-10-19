package com.tudelft.comparison;

import com.tudelft.paillier.PaillierContext;
import com.tudelft.paillier.PaillierPublicKey;

import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;

class DatabaseEntry
{
	private BigInteger name;
	private int        bitLengthName;
	private BigInteger age;
	private int        bitLengthAge;
	private BigInteger income;
	private int        bitLengthIncome;

	DatabaseEntry()
	{
		name = Generator.randName();
		bitLengthName = name.bitLength();
		age = Generator.randAge();
		bitLengthAge = age.bitLength();
		income = Generator.randIncome();
		bitLengthIncome = income.bitLength();
	}
	static DatabaseEntry encryptEntry(DatabaseEntry entry, PaillierPublicKey pk)
	{
		try
		{
			PaillierContext context = pk.createSignedContext();
			
			entry.setName(context.encode(entry.getName())
					.encrypt()
					.getCipherText());
			entry.setAge(context.encode(entry.getAge())
					.encrypt()
					.getCipherText());
			entry.setIncome(context.encode(entry.getIncome())
					.encrypt()
					.getCipherText());
		}
		catch(Exception e) { e.printStackTrace(); }

		return entry;
	}
	BigInteger get(Config.column column)
	{
		BigInteger value = BigInteger.valueOf(-1);

		try
		{
			String columnName = column.toString().toLowerCase();
			String getterName = "get" + columnName.substring(0, 1).toUpperCase() + columnName.substring(1);

			value = ((BigInteger) this.getClass().getDeclaredMethod(getterName).invoke(this));
		}
		catch(IllegalAccessException | InvocationTargetException | NoSuchMethodException e)
		{
			e.printStackTrace();
		}
		return value;
	}
	int getBitLength(Config.column column)
	{
		Integer value = -1;

		try
		{
			String columnName = column.toString().toLowerCase();
			String getterName = "getBitLength" + columnName.substring(0, 1).toUpperCase() + columnName.substring(1);

			value = ((Integer) this.getClass().getDeclaredMethod(getterName).invoke(this));
		}
		catch(IllegalAccessException | InvocationTargetException | NoSuchMethodException e)
		{
			e.printStackTrace();
		}
		return value;
	}
	BigInteger getName()
	{
		return name;
	}
	void setName(BigInteger name)
	{
		this.name = name;
	}
	int getBitLengthName()
	{
		return bitLengthName;
	}
	void setBitLengthName(int bitLengthName)
	{
		this.bitLengthName = bitLengthName;
	}
	BigInteger getAge()
	{
		return age;
	}
	void setAge(BigInteger age)
	{
		this.age = age;
	}
	int getBitLengthAge()
	{
		return bitLengthAge;
	}
	void setBitLengthAge(int bitLengthAge)
	{
		this.bitLengthAge = bitLengthAge;
	}
	BigInteger getIncome()
	{
		return income;
	}
	void setIncome(BigInteger income)
	{
		this.income = income;
	}
	int getBitLengthIncome()
	{
		return bitLengthIncome;
	}
	void setBitLengthIncome(int bitLengthIncome)
	{
		this.bitLengthIncome = bitLengthIncome;
	}
}