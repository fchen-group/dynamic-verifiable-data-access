package fchen;

import java.security.*;
import java.util.Arrays;

/**
 * This class implements the hash authentication tree primitive. The hash tree
 * is stored in an array and indexed according to the node position in the
 * complete binary tree. The root node is stored at index 0;
 * 
 * index caculations:
 * 0
 * 1,2
 * 3,4,5,6
 * 7,8,9,10,11,12,13,14
 * Height i, start index 2^i-1, end index 2^i-1+2^i-1, j-th element index 2^i-1+j where 0¡Üj¡Ü2^i-1
 * Height i, Suppose j is even, what are the indices of its children?
 * Left child: 2j +2^i-(j+1) there are 2j elements for the children before j, there are 2^i-(j+1) element after j, thus the index is ¡¼(2¡½^i-1+j)+(2j) +2^i-(j+1)+1=2^(i+1)+2j-1
 * Right child: 2^(i+1)+2j-1
 * Height i+1, start index 2^(i+1)-1, end index 2^(i+1)-1+2^(i+1)-1, j-th element index 2^(i+1)-1+j where 0¡Üj¡Ü2^(i+1)-1
 * 
 * @author Chen, Fei (https://sites.google.com/site/chenfeiorange/)
 * @author Last revision on 15-01-2020
 * @author Email: chenfeiorange@163.com
 */
public class HashTree {
	private byte[][] ht = null; 
	// first dimension stores all nodes; second dimension stores the hash value
	private int treeSize = 0;
	private int treeHeight = 0;
	private MetaProofData[] leaf = null;
	private MessageDigest md = null; // SHA-256 is used here

	/**
	 * This function constructs the hash authentication tree using the leaf nod
	 * provided.
	 * 
	 * @param treeHeight - This parameter can also be calculated using the size of the leaf nodes.
	 * @param leaf       - The leaf nodes
	 */
	public HashTree(int treeHeight, MetaProofData[] leaf) {
		this.treeHeight = treeHeight;
		this.treeSize = 2 * (int) Math.pow(2, this.treeHeight) - 1; 	// complete binary tree
		this.leaf = leaf;

		try {
			this.md = MessageDigest.getInstance("SHA-256");
		} catch (Exception e) {
			System.out.println("get SHA-256 instance error");
			System.out.println(e);
		}

		ht = new byte[this.treeSize][];
		// construct the bottom level of the hash tree
		int first = (int) Math.pow(2, this.treeHeight) - 1;
		int end = this.treeSize;
		for (int i = first; i < end; i++) {
			ht[i] = leaf[i - first].generateHash();
		}
	}

	/**
	 * This function checks whether an authentication path is correct.
	 * 
	 * @param authenticationPath
	 *            - An authentication path from the bottom to the root. The root
	 *            value is at the end of the array.
	 * @param root
	 *            - The root value of an hash tree.
	 * @return - If it is correct, return true; else false.
	 */
	public static boolean verify(byte[][] authenticationPath, byte[] root) {
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("SHA-256");
		} catch (Exception e) {
			System.out.println("get SHA-256 instance error - static verify");
			System.out.println(e);
		}

		int height = (authenticationPath.length - 1) / 2;
		byte[] temp = null;
		int cheatFlag = 0;

		for (int i = 0; i < height - 1; i++) // calculate hash values from the bottom to the top
		{
			md.update(authenticationPath[2 * i]);
			temp = md.digest(authenticationPath[2 * i + 1]);

			if (Arrays.equals(temp, authenticationPath[2 * i + 2]) == false
					&& Arrays.equals(temp, authenticationPath[2 * i + 3]) == false)
				cheatFlag = cheatFlag + 1;
		}

		md.update(authenticationPath[2 * height - 2]);
		temp = md.digest(authenticationPath[2 * height - 1]);

		if (Arrays.equals(temp, authenticationPath[2 * height]) == false)
			cheatFlag = cheatFlag + 1;

		if (Arrays.equals(root, authenticationPath[2 * height]) == false)
			cheatFlag = cheatFlag + 1;

		if (cheatFlag == 0)
			return true;
		else
			return false;
	}

	/**
	 * This function builds the whole hash tree from the bottom to the top. The root
	 * value is at index 0;
	 */
	public void build() {
		for (int height = this.treeHeight - 1; height >= 0; height--) {
			int first = (int) Math.pow(2, height) - 1;
			int end = first + (int) Math.pow(2, height);

			for (int i = first; i < end; i++) {
				this.md.update(ht[2 * i + 1]);
				ht[i] = this.md.digest(ht[2 * i + 2]);
			}
		}
	}
	
	public void update(int position, MetaProofData leaf) {
		
		this.leaf[position] = leaf; // a bug found later
		
		int first = (int) Math.pow(2, this.treeHeight) - 1;
		position = position + first;
		this.ht[position] = leaf.generateHash();
		
		for (int height = this.treeHeight; height >= 1; height--) {
			if (position % 2 == 0)
				position = position -1;
			this.md.update(ht[position]);
			ht[(position - 1)/2] = this.md.digest(ht[position + 1]);
			position = (position - 1)/2;
		}
	}

	/**
	 * This function gets the root hash value of the hash tree.
	 * 
	 * @return - The root hash value
	 */
	public byte[] getRoot() {
		return ht[0];
	}

	/**
	 * This function gets the authentication path for the node with index 'index'.
	 * 
	 * @param index
	 *            - The index of the leaf node which is to be authenticated. It
	 *            starts with 0.
	 * @return - An authentication path from the bottom to the top, with
	 *         corresponding index becoming large
	 */
	public byte[][] getAuthenticationPath(int index) {
		byte[][] result = new byte[2 * this.treeHeight + 1][];

		if (index % 2 == 0)
			index = (int) Math.pow(2, this.treeHeight) - 1 + index;
		else
			index = (int) Math.pow(2, this.treeHeight) - 1 + index - 1;

		for (int i = 0; i <= 2 * this.treeHeight - 2; i = i + 2) // note that i = i + 2
		{
			result[i] = ht[index];
			result[i + 1] = ht[index + 1];
			index = (index - 1) / 2;

			if (index % 2 == 0)
				index = index - 1;// pay attention; this bug is discovered later
		}

		result[2 * this.treeHeight] = ht[0]; // pay attention; this bug is discovered later

		return result;
	}

	/**
	 * This funtion prints out the whole hash tree.
	 */
	public void print() {
		for (int height = 0; height <= this.treeHeight; height++) {
			int first = (int) Math.pow(2, height) - 1;
			int end = first + (int) Math.pow(2, height);

			System.out.println("*******************");
			System.out.println("height: " + height);
			for (int i = first; i < end; i++) {
				System.out.println(DynamicVFS.bytes2HexString(this.ht[i]));
			}
			System.out.println("*******************");
		}
	}
	
	public void printRoot() {
		System.out.println(DynamicVFS.bytes2HexString(this.ht[0]));
	}
	
	

//	private byte[] int2byteArray(int num) {
//		byte[] result = new byte[4];
//
//		result[3] = (byte) (num >>> 24);
//		result[2] = (byte) (num >>> 16);
//		result[1] = (byte) (num >>> 8);
//		result[0] = (byte) (num);
//
//		return result;
//	}

	public byte[][] getHt() {
		return ht;
	}

	public void setHt(byte[][] ht) {
		this.ht = ht;
	}

	public int getTreeSize() {
		return treeSize;
	}

	public void setTreeSize(int treeSize) {
		this.treeSize = treeSize;
	}

	public int getTreeHeight() {
		return treeHeight;
	}

	public void setTreeHeight(int treeHeight) {
		this.treeHeight = treeHeight;
	}

	public MetaProofData[] getLeaf() {
		return leaf;
	}

	public void setLeaf(MetaProofData[] leaf) {
		this.leaf = leaf;
	}

	public MessageDigest getMd() {
		return md;
	}

	public void setMd(MessageDigest md) {
		this.md = md;
	}
}
