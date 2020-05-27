package fchen;

/**
 * It checks the correctness of the protocol.
 * 
 * @author Chen, Fei (https://sites.google.com/site/chenfeiorange/)
 * @author Last revision on 15-01-2020
 * @author Email: chenfeiorange@163.com
 */
public class CorrectnessCheck {
	public static void main(String[] args) {
		String rootDirectory = "D:\\test\\files\\test1"; // This directory contains all files listed below.
		String[] allFiles = { "a", "aaa", "ab1", "b23", "c" };

		DynamicVFS test = new DynamicVFS(rootDirectory, 0.5);
		test.prepareOutsource();
		test.outsource();

		System.out.println("The hash tree is as follows:");
		test.getHashTree().print();
		System.out.println("query and verification tests:");
		run(test, allFiles);
		
		System.out.println("root value initial:");
		test.getHashTree().printRoot();
		
		System.out.println("\ndelete and add operation tests:\n");
		String deletedFile = "aaa";
		byte[] query = test.query(deletedFile);
		test.delete(query);		
		test.getHashTree().print();
		allFiles = new String[] {"a", "aaa", "c"};
		run(test, allFiles);
		
		System.out.println("root value after delete:");
		test.getHashTree().printRoot();
		
		String addedFile = "aaa";
		query = test.query(addedFile);
		test.add(query);
		
		System.out.println("root value after add:");
		test.getHashTree().printRoot();
		
		allFiles = new String[] {"aaa", "c"};
		run(test, allFiles);		
	}
	
	private static void run(DynamicVFS protocol, String[] allFiles) {
		for (String temp : allFiles) {
			byte[] query = protocol.query(temp);
			System.out.println("\nthe query file is: " + temp + " ; " + DynamicVFS.bytes2HexString(query));

			ProofData proof = null;
			proof = protocol.search(query);
			System.out.println("The proof is:\n");
			proof.print();

			boolean result = protocol.verify(query, proof);
			if (result == true)
				System.out.println("verification succesful. (The cloud is honest.)\n");
			else
				System.out.println("verificatio failed. (The cloud cheats.)\n");
		}
	}

}
