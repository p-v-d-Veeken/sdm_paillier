package com.tudelft.comparison;

import java.util.Scanner;

public class Main
{
	private static Scanner scanner = new Scanner(System.in);

	public static void main(String[] args) throws Exception
	{
		System.out.print("Please enter an assignment number, or `exit` to quit program:\n> " );

		while(true)
		{
			boolean skipPrint = false;
			String  input     = scanner.nextLine();

			switch(input)
			{
				case "1":
					Assignment.assignment1(scanner);
					break;
				case "2":
					Assignment.assignment2(scanner);
					break;
				/*case "3":
					Assignment.assignment3(scanner);
					break;*/
				case "exit":
					System.out.println("Bye bye!");
					System.exit(0);
					break;
				case "":
					skipPrint = true;
					break;
				default:
					System.out.println("Assignment number not recognized");
					break;
			}
			System.out.print(!skipPrint ? "Please enter an assignment number, or `exit` to quit program:\n> " : "");
		}
	}
}