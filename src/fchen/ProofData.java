package fchen;

import java.util.ArrayList;

/**
 * This class encapsulates the search result returned by the cloud, together
 * with its correctness proof.
 * 
 * @author Chen, Fei (https://sites.google.com/site/chenfeiorange/)
 * @author Last revision on 15-01-2020
 * @author Email: chenfeiorange@163.com
 */
public class ProofData {
	private byte[] queryFile = null; // queried filename MAC
	private int existingFlag = -1; // 1: file exists; 0: file not exist
	
	// the number of total authentication paths which are introduced by collisions in the
	// process mapping a filename to an index
	private int totalItems = 0;	
	private ArrayList<MetaProofData> authentication = null; // authentication paths

	// On constructing, only the quried filename is needed.
	// Other fields are filled subsequently.
	public ProofData(byte[] queryFile) {
		super();
		this.queryFile = queryFile;
		this.authentication = new ArrayList<MetaProofData>();
		this.totalItems = 0;
	}

	public void addProofData(MetaProofData temp) {
		this.authentication.add(temp);
		this.totalItems = this.totalItems + 1;
	}

	/**
	 * This function checks whether the proof is correct on its own.
	 * 
	 * @param leafSize - number of total leaves
	 * @param root     - the root Hash value of the authentication tree
	 * @return If the returned result from the cloud is correct, return true; else false.
	 */
	public boolean validate(int leafSize, byte[] root) {
		int cheatFlag = 0;
		int indexExpected = -1;

		indexExpected = ((int) queryFile[0]) + (((int) queryFile[1]) << 8) + (((int) queryFile[2]) << 16)
				+ (((int) queryFile[3]) << 24); // calculate h_1(x)
		indexExpected = Math.abs(indexExpected) % leafSize;

		MetaProofData metaData = this.authentication.get(0);
		if (metaData.getIndex() != indexExpected || metaData.validate(root) == false)
			cheatFlag = cheatFlag + 1;

		if (this.totalItems == 1) {
			if (cheatFlag == 0)
				return true;
			else
				return false;
		}

		indexExpected = ((int) queryFile[4]) + (((int) queryFile[5]) << 8) + (((int) queryFile[6]) << 16)
				+ (((int) queryFile[7]) << 24); // calculate h_2
		indexExpected = Math.abs(indexExpected) % leafSize;
		metaData = this.authentication.get(1);
		if (metaData.getIndex() != indexExpected)
			cheatFlag = cheatFlag + 1;
		if (metaData.validate(root) == false)
			cheatFlag = cheatFlag + 1;

		if (this.totalItems == 2) {
			if (cheatFlag == 0)
				return true;
			else
				return false;
		}

		// from now on, the index could be easily calculated; the complexity
		// comes from the index finding process.
		for (int i = 2; i < this.totalItems; i++) {
			indexExpected = (indexExpected + 101) % leafSize;
			metaData = this.authentication.get(i);
			if (metaData.getIndex() != indexExpected || metaData.validate(root) == false)
				cheatFlag = cheatFlag + 1;
		}

		if (cheatFlag == 0)
			return true;
		else
			return false;
	}

	/**
	 * This function prints out the whole proof data.
	 */
	public void print() {
		System.out.println("existing flag: " + this.existingFlag);
		System.out.println("total items: " + this.totalItems);
		System.out.println("query file: " + DynamicVFS.bytes2HexString(this.queryFile));

		for (int i = 0; i < this.totalItems; i++)
			this.authentication.get(i).print();		
	}

	public int getExistingFlag() {
		return existingFlag;
	}

	public void setExistingFlag(int existingFlag) {
		this.existingFlag = existingFlag;
	}

	public int getTotalItems() {
		return totalItems;
	}

	public void setTotalItems(int totalItems) {
		this.totalItems = totalItems;
	}

	public byte[] getQueryFile() {
		return queryFile;
	}

	public void setQueryFile(byte[] queryFile) {
		this.queryFile = queryFile;
	}

	/**
	 * This function gets the i-th authentication path, where 'i' starts with index
	 * 0.
	 * 
	 * @param i
	 *            - index
	 * @return An authentication path
	 */
	public MetaProofData getAuthentication(int i) {
		return this.authentication.get(i);
	}

	/**
	 * This function sets the i-th authentication path.
	 * 
	 * @param i      - index
	 * @param proof  - The meta proof data
	 */
	public void setAuthentication(int i, MetaProofData proof) {
		this.authentication.set(i, proof);
	}

}
