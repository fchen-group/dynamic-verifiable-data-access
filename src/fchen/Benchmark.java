package fchen;

import com.javamex.classmexer.*;

/**
 * This class measure the performance of our verifiable file search algorithm on
 * a certain directory. The performance metric includes the storage for storing
 * the hash tree, the outsourcing time, the query time, the search time, and the
 * verification time. We divide the search and verification time into two cases:
 * one for existing files and the other for non-existing files.
 * 
 * @author Chen, Fei (https://sites.google.com/site/chenfeiorange/)
 * @author Last revision on 15-01-2020
 * @author Email: chenfeiorange@163.com
 * 
 */
public class Benchmark {
	private long storage = 0; // storage for the file set and the prefix set
	private long proofSize[] = null; // 0: proof data for existing files
										// 1: proof data for non-existing files
	private long time[]; // time for outsource, query, search existing, search
	// nonexisting, verify existing, verify nonexisting,
	// indexed by 0, 1, 2, 3, 4, 5, respectively
	private int collisionCount[][] = null; // number of collisions for existing and non-existing files,
											// indexed by 0, 1, respectively.
	private String directory;

	public final static int LOOP_TIMES = 40; // we run the performance
	// evaluation for such times and
	// then average the result.

	public Benchmark(String directory) {
		super();
		this.directory = directory;
		this.storage = 0;
		this.time = new long[8];
		this.proofSize = new long[2];

		this.proofSize[0] = 0;
		this.proofSize[1] = 0;
		for (int i = 0; i < this.time.length; i++)
			this.time[i] = 0;

		this.collisionCount = new int[2][LOOP_TIMES];
		for (int i = 0; i < 2; i++)
			for (int j = 0; j < LOOP_TIMES; j++)
				this.collisionCount[i][j] = 0;
	}

	public long getStorage() {
		return storage;
	}

	public void setStorage(long storage) {
		this.storage = storage;
	}

	public long[] getTime() {
		return time;
	}

	public void setTime(long[] time) {
		this.time = time;
	}

	public String getDirectory() {
		return directory;
	}

	public void setDirectory(String directory) {
		this.directory = directory;
	}

	/**
	 * This is the main function to evaluate the performance.
	 */
	public void run() {
		DynamicVFS instance = new DynamicVFS(this.directory, 0.1);

		long startTime = 0, endTime = 0, startMemory = 0, endMemory = 0;

		Runtime r = Runtime.getRuntime();

		r.gc();
		startTime = System.nanoTime();
		instance.prepareOutsource();
		startMemory = r.freeMemory();
		instance.outsource();
		endMemory = r.freeMemory();
		endTime = System.nanoTime();

		this.storage = startMemory - endMemory;
		// if the memory cost cannot be measured approximately using "Runtime" class,
		// another more refined utility class is employed.
		// For the "MemoryUtil" class, please refer to
		// "http://www.javamex.com/classmexer/api/".
		if (this.storage == 0)
			this.storage = MemoryUtil.deepMemoryUsageOf(instance.getHashTree());

		this.time[0] = endTime - startTime;

		for (int i = 0; i < LOOP_TIMES; i++) {
			String queryExisisting = instance.getRandomExistingFile();
			ProofData proof = null;

			startTime = System.nanoTime();
			byte[] query = instance.query(queryExisisting);
			endTime = System.nanoTime();
			this.time[1] = this.time[1] + (endTime - startTime);

			startTime = System.nanoTime();
			proof = instance.search(query);
			endTime = System.nanoTime();
			this.time[2] = this.time[2] + (endTime - startTime);
			this.proofSize[0] = this.proofSize[0] + MemoryUtil.deepMemoryUsageOf(proof);

			this.collisionCount[0][i] = proof.getTotalItems();

			startTime = System.nanoTime();
			instance.verify(query, proof);
			endTime = System.nanoTime();
			this.time[4] = this.time[4] + (endTime - startTime);
			
			startTime = System.nanoTime();
			instance.delete(query);
			endTime = System.nanoTime();
			this.time[6] = this.time[6] + (endTime - startTime);
			
			startTime = System.nanoTime();
			instance.add(query);
			endTime = System.nanoTime();
			this.time[7] = this.time[7] + (endTime - startTime);			
		}

		this.time[1] = (long) (this.time[1] / LOOP_TIMES);
		this.time[2] = (long) (this.time[2] / LOOP_TIMES);
		this.time[4] = (long) (this.time[4] / LOOP_TIMES);
		this.time[6] = (long) (this.time[6] / LOOP_TIMES);
		this.time[7] = (long) (this.time[7] / LOOP_TIMES);
		this.proofSize[0] = (long) (this.proofSize[0] / LOOP_TIMES);

		for (int i = 0; i < LOOP_TIMES; i++) {
			String queryNonExisisting = instance.getRandomNonExistingFile();
			ProofData proof = null;
			byte[] query = instance.query(queryNonExisisting);

			startTime = System.nanoTime();
			proof = instance.search(query);
			endTime = System.nanoTime();
			this.time[3] = this.time[3] + (endTime - startTime);
			this.proofSize[1] = this.proofSize[1] + MemoryUtil.deepMemoryUsageOf(proof);

			this.collisionCount[1][i] = proof.getTotalItems();

			startTime = System.nanoTime();
			instance.verify(query, proof);
			endTime = System.nanoTime();
			this.time[5] = this.time[5] + (endTime - startTime);
		}

		this.time[3] = (long) (this.time[3] / LOOP_TIMES);
		this.time[5] = (long) (this.time[5] / LOOP_TIMES);
		this.proofSize[1] = (long) (this.proofSize[1] / LOOP_TIMES);

		System.out.println("TEST CASE: " + this.directory + "\n");
		System.out.println("storage is: " + this.storage + "Bytes");
		System.out.println("time is: (ns)");
		for (int i = 0; i < this.time.length; i++)
			System.out.print(this.time[i] + "    ");
		System.out.println(
				"\ncorrespoding to outsource (0), query(1), search existing(2), search nonexisting(3), verify existing(4), verify nonexisting(5), delete(6), add(7)");


		System.out.println("Statistic about the number of collisons for existing files are as follows:");
		this.computeStatistic(this.collisionCount[0]);
		System.out.println("Statistic about the number of collisons for non-existing files are as follows:");
		this.computeStatistic(this.collisionCount[1]);

		System.out.println("communication cost for querying an existing file is: " + this.proofSize[0]);
		System.out.println("communication cost for querying a non-existing file is: " + this.proofSize[1]);

	}

	private void computeStatistic(int data[]) {
		int min = data[0], max = data[0], sum = 0;
		for (int i = 0; i < data.length; i++) {
			sum = sum + data[i];
			if (data[i] < min)
				min = data[i];
			if (data[i] > max)
				max = data[i];
		}

		System.out.println("The minimal value is: " + min);
		System.out.println("The maximal value is: " + max);
		System.out.println("The average value is: " + (double) sum / data.length);
	}
}
