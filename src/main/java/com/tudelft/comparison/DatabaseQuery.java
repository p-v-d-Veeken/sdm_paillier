package com.tudelft.comparison;

class DatabaseQuery
{
/*
	private Paillier paillier;
	private Database database;

	DatabaseQuery(Paillier paillier, Database database)
	{
		this.paillier = paillier;
		this.database = database;
	}
	List<DatabaseEntry> findGreaterThan(Config.column column, BigInteger value, int bitLength) throws Exception
	{
		if(column.equals(Config.column.NAME))
		{
			throw new Exception("Non-numeric column specified.");
		}
		return database.getEntriesStream()
			.filter(entry -> compare(entry.get(column), value, entry.getBitLength(column), bitLength))
			.collect(Collectors.toList());
	}
	private boolean compare(BigInteger a, BigInteger b, int bitLengthA, int bitLengthB)
	{
		try
		{
			SecureComparison comp = new SecureComparison(paillier);
			BigInteger       res  = paillier.decrypt(comp.compare(a, b, Integer.max(bitLengthA, bitLengthB)));

			return res.equals(BigInteger.ONE);
		}
		catch(Exception e) { e.printStackTrace(); }

		return false;
	}
*/
}