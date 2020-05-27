package fchen;

import java.util.*;
import java.security.*;
import javax.crypto.*;
import java.io.*;

/**
 * This class implements the protocol of verifiable encrypted file search on a
 * cloud. The basic tool is the hash authentication tree.
 * 
 * @author Chen, Fei (https://sites.google.com/site/chenfeiorange/)
 * @author Last revision 15-01-2020
 * @author Email: chenfeiorange@163.com
 *
 */
public class DynamicVFS {
	private String rootDirectory = null; // system parameter; files to be outsourced
	private int hashSize = 32; // system parameter; depends on the HASH algorithm used; 32 * 8byte = 256bits
	private byte[] specialFile = null; // system parameter; denotes all non-existing files

	private byte[] seed = null; // used for HMAC to protect filename privacy
	private SecureRandom sr = null; // used for key generator
	private KeyGenerator kg = null; // key generator to generate a secrete key
	private SecretKey sk = null; // secret key for HMAC
	private Mac mac = null;

	private MetaProofData[] leafFiles = null; // one part of the outsourced data: index + filename MAC
	private HashTree ht = null; // the other part of the outsourced data: hash(index + filename MAC)
	private byte[] root = null; // the root value of the hash tree

	private int currentSize = 0; // performance parameter;
	private int leafSize = 0; // performance parameter; 8 * # of maximal files
	private int treeHeight = 0;
	private int treeSize = 0;
	private double loadFactor = 0.1; // performance parameter;
	private byte[] visited = null; // indicating whether an index has been used when allocating indices

	/**
	 * It constructs the main object.
	 * 
	 * @param rootDirectory - the directory to be outsourced
	 */
	public DynamicVFS(String rootDirectory) {
		super();
		this.rootDirectory = rootDirectory;

		this.specialFile = new byte[this.hashSize];
		for (int i = 0; i < this.hashSize; i++)
			this.specialFile[i] = 0;

		this.loadFactor = 0.1;
		this.KeyGen();

		try {
			this.sr = new SecureRandom(this.seed);
			this.kg = KeyGenerator.getInstance("HmacSHA256");
			this.kg.init(this.sr);
			this.sk = kg.generateKey();
			this.mac = Mac.getInstance("HmacSHA256");
			this.mac.init(sk);
		} catch (Exception e) {
			System.out.println("Error occured when initializing HmacSHA256.");
		}
	}

	public DynamicVFS(String rootDirectory, double loadFactor) {
		super();
		this.rootDirectory = rootDirectory;

		this.specialFile = new byte[this.hashSize];
		for (int i = 0; i < this.hashSize; i++)
			this.specialFile[i] = 0;

		this.loadFactor = loadFactor;
		this.KeyGen();

		try {
			this.sr = new SecureRandom(this.seed);
			this.kg = KeyGenerator.getInstance("HmacSHA256");
			this.kg.init(this.sr);
			this.sk = kg.generateKey();
			this.mac = Mac.getInstance("HmacSHA256");
			this.mac.init(sk);
		} catch (Exception e) {
			System.out.println("Error occured when initializing HmacSHA256.");
		}
	}

	/**
	 * This function generates the secret key used in the protocol. We fix the
	 * secret key in the experiments; in practice, this is set by the data owner.
	 */
	public void KeyGen() {
		this.seed = new byte[32];
		for (int i = 0; i < this.seed.length; i++)
			this.seed[i] = (byte) 0xff;
	}

	/**
	 * The function does some preparation work for outsourceing. This is used for
	 * performance evaluation.
	 */
	public void prepareOutsource() {
		// leaf node of the hash tree: index + filename HMAC + hash value of the above
		// two
		// two hash functions will be used to find the index in the hash tree.
		// h_1(x) = x % hash_tree_size
		// h_2(x) = 11 * x + 100 % hash_tree_size
		File directory = new File(this.rootDirectory);
		String[] allFiles = directory.list();

		this.currentSize = allFiles.length;
		this.treeHeight = (int) Math.ceil(Math.log(this.currentSize / this.loadFactor) / Math.log(2));
		this.leafSize = (int) Math.pow(2, this.treeHeight);
		this.treeSize = 2 * this.leafSize - 1;
		this.visited = new byte[this.leafSize];

		for (int i = 0; i < this.leafSize; i++)
			this.visited[i] = 0;

		this.leafFiles = new MetaProofData[this.leafSize];

		// for those empty slots in the leaf nodes, assign the MAC value all zero which is regarded as special non-existing file MACs.
		for (int i = 0; i < this.leafSize; i++)
			this.leafFiles[i] = new MetaProofData(i, this.specialFile, 0);				

		for (String file : allFiles) {
			byte[] fileMac = this.mac.doFinal(file.getBytes());

			int index = 0;
			index = ((int) fileMac[0]) + (((int) fileMac[1]) << 8) + (((int) fileMac[2]) << 16)
					+ (((int) fileMac[3]) << 24); // a bug is fixed here
			index = Math.abs(index) % this.leafSize; // h_1

			if (visited[index] == 1) {
				index = ((int) fileMac[4]) + (((int) fileMac[5]) << 8) + (((int) fileMac[6]) << 16)
						+ (((int) fileMac[7]) << 24);
				index = Math.abs(index) % this.leafSize; // h_2
			}

			while (visited[index] == 1) {
				index = (index + 101) % this.leafSize; // probing hashes; this should seldom happen.
			}

			for (int i = 0; i < fileMac.length; i++)
				this.leafFiles[index].setFilename(fileMac);

			visited[index] = 1;
		}
	}

	/**
	 * This function helps a data owner outsource the data. The data owner only
	 * keeps the secret key and the root value of the hash tree.
	 */
	public void outsource() {
		this.ht = new HashTree(this.treeHeight, this.leafFiles);
		this.ht.build();
		this.root = this.ht.getRoot();
	}

	/**
	 * This function helps a data user generate a query token when he wants to fetch
	 * a file from the cloud.
	 * 
	 * @param file
	 *            - the filename of the queried file
	 * @return - its MAC
	 */
	public byte[] query(String file) {
		byte[] fileMac = this.mac.doFinal(file.getBytes());

		return fileMac;
	}

	/**
	 * This function helps a cloud answer a query of a data user by searching all
	 * the files.
	 * 
	 * @param queryFile - a query token send by the data user
	 * @return the query result represented by the data class 'ProofData'
	 */
	public ProofData search(byte[] queryFile) {
		int index = 0;
		index = ((int) queryFile[0]) + (((int) queryFile[1]) << 8) + (((int) queryFile[2]) << 16)
				+ (((int) queryFile[3]) << 24);
		index = Math.abs(index) % this.leafSize;

		ProofData proof = new ProofData(queryFile);
		MetaProofData tuple = null;
		int flag = 0; // used to choose proper index

		while (flag == 0 || flag == 1) {
			tuple = (ht.getLeaf())[index];			
			tuple.setAuthenticationPath(this.ht.getAuthenticationPath(index));			
			proof.addProofData(tuple);
			
			byte[] filename = tuple.getFilename();
			int state = tuple.getState();
			
			if (Arrays.equals(filename, queryFile)) {				
				proof.setExistingFlag(1);
				flag = 2; // file exists
			} else if (Arrays.equals(filename, this.specialFile) && state == 0) {
				proof.setExistingFlag(0);
				flag = 3; // file does not exist				
			} else if (flag == 0) {
				index = ((int) queryFile[4]) + (((int) queryFile[5]) << 8) + (((int) queryFile[6]) << 16)
						+ (((int) queryFile[7]) << 24);
				index = Math.abs(index) % this.leafSize; // h_2
				flag = 1; // change index
			} else
				index = (index + 101) % this.leafSize; // probing hashes; this should seldom happen.
		}

		return proof;
	}

	/**
	 * This function helps a data user to check whether the returned result from the
	 * cloud is correct.
	 * 
	 * @param queryFile - the query token sent to the cloud by the data user
	 * @param proof - the returned result from the cloud
	 * @return true if the cloud is honest; false if the cloud cheats
	 */
	public boolean verify(byte[] queryFile, ProofData proof) {
		int cheatFlag = 0;

		if (proof.getExistingFlag() == 1) // file exists
		{
			if (Arrays.equals(proof.getQueryFile(), queryFile) == false
					|| proof.validate(this.leafSize, this.root) == false)
				cheatFlag = cheatFlag + 1;

			int lastIndex = proof.getTotalItems() - 1;
			MetaProofData last = proof.getAuthentication(lastIndex);
			if (Arrays.equals(last.getFilename(), queryFile) == false || last.getState() != 0)
				cheatFlag = cheatFlag + 1;

			if (cheatFlag == 0)
				return true;
			else
				return false;
		} else {
			if (Arrays.equals(proof.getQueryFile(), queryFile) == false
					|| proof.validate(this.leafSize, this.root) == false)
				cheatFlag = cheatFlag + 1;

			int lastIndex = proof.getTotalItems() - 1;
			MetaProofData last = proof.getAuthentication(lastIndex);
			if (Arrays.equals(last.getFilename(), this.specialFile) == false || last.getState() != 0)
				cheatFlag = cheatFlag + 1;

			if (cheatFlag == 0)
				return true;
			else {
				System.out.println("cheatFlag: " + cheatFlag);
				return false;
			}				
		}
	}

	/**
	 * Delete a file in the outsourced data. It first searches whether the file exisits.
	 * If the file does exist, find it, update its state to 1 and its filename to the
	 * special filename, and update the hash tree.
	 * @param queryFile - the pseudorandom filename masked by a MAC
	 */
	public void delete(byte[] queryFile){
		ProofData proof = this.search(queryFile);
		if (proof.getExistingFlag() == 0)
				return;
		
		int temp = proof.getTotalItems();
		MetaProofData deletedFile = proof.getAuthentication(temp - 1);
		deletedFile.setState(1);
		deletedFile.setFilename(this.specialFile);
		this.ht.update(deletedFile.getIndex(), deletedFile);
		this.root = this.ht.getRoot(); //a bug later found
	}
	
	/**
	 * Add a new file in the outsourced data. It first searches whether the file exisits.
	 * If the file does not exist, find a suitable slot in the search path and update this
	 * slot, and update the hash tree.
	 * @param queryFile - the pseudorandom filename masked by a MAC
	 */
	public void add(byte[] queryFile)
	{
		ProofData proof = this.search(queryFile);
		if (proof.getExistingFlag() == 1)
				return;
		
		int position = -1;
		// first search whether there is a deleted slot
		for (int i = 0; i < proof.getTotalItems(); i++) {
			MetaProofData metaProof = proof.getAuthentication(i);
			if (metaProof.getState() == 1) {
				position = metaProof.getIndex();
				break;
			}			
		}
		
		//if there is no deleted slot, set the inserted position as the last slot in the searched slots
		if (position == -1)
			position = proof.getAuthentication(proof.getTotalItems() - 1).getIndex();
		
		MetaProofData addedFile = new MetaProofData(position, queryFile, 0);
		this.ht.update(position, addedFile);
		this.root = this.ht.getRoot();
	}
	
	private final static byte[] hex = "0123456789ABCDEF".getBytes();

	/**
	 * It transforms a byte array into a string in the Hexadecimal format in an
	 * entry-wise way.
	 * 
	 * @param b
	 *            The byte array.
	 * @return The hexadecimal string.
	 */
	public static String bytes2HexString(byte[] b) {
		byte[] buff = new byte[2 * b.length];
		for (int i = 0; i < b.length; i++) {
			buff[2 * i] = hex[(b[i] >> 4) & 0x0f];
			buff[2 * i + 1] = hex[b[i] & 0x0f];
		}
		return new String(buff);
	}

	/**
	 * This function generates a random existing filename. It is used for
	 * performance evaluation.
	 * 
	 * @return - an existing filename
	 */
	public String getRandomExistingFile() {
		File directory = new File(this.rootDirectory);
		String[] allFiles = directory.list();

		int r = (int) Math.floor(Math.random() * allFiles.length);
		return allFiles[r];
	}

	/**
	 * This function generates a random non-existing filename. It is used for
	 * performance evaluation.
	 * 
	 * @return - a non-existing filename
	 */
	public String getRandomNonExistingFile() {
		int r = (int) Math.floor(Math.random() * 1000);
		return String.valueOf(r) + "?!";
	}

	public double getLoadFactor() {
		return this.currentSize / this.leafSize;

	}

	public int getTreeSize() {
		return this.treeSize;
	}

	public HashTree getHashTree() {
		return ht;
	}

	public void setHashTree(HashTree ht) {
		this.ht = ht;
	}
}
