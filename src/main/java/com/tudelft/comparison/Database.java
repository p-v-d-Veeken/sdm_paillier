package com.tudelft.comparison;

import com.tudelft.paillier.PaillierPublicKey;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

class Database
{
	private List<DatabaseEntry> entries;

	Database(int size)
	{
		entries = new ArrayList<>(size);

		for(int i = 0; i < size; i++)
		{
			DatabaseEntry entry = new DatabaseEntry();

			entries.add(entry);
		}
	}
	void encryptDatabase(PaillierPublicKey pk)
	{
		entries = entries.stream()
			.parallel()
			.map(entry -> DatabaseEntry.encryptEntry(entry, pk))
			.collect(Collectors.toList());
	}
	Stream<DatabaseEntry> getEntriesStream()
	{
		return entries.parallelStream();
	}
}