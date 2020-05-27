package fchen;

import java.security.MessageDigest;
import java.util.Arrays;

/**
 * This class encapsulates the tuple (index, filename, state, authentication path) and
 * some corresponding methods.
 * It is used in two cases. One case is to use this class as the leaf level data for
 * building the hash authentication tree. In this case, the field 'authenticationPath'
 * is not used.
 * Another case is to use it as a part of the search result. Now the field 'authenticationPath'
 * is used. The cloud could return a few of such tuples because of the hash collisions.
 * 
 * @author Chen, Fei (https://sites.google.com/site/chenfeiorange/)
 * @author last revision on 15-01-2020
 * @author Email: chenfeiorange@163.com
 * 
 */
public class MetaProofData {
	private int index = -1; // index of the leafnode
	private byte[] filename = null; // filename of the leafnode
	private int state = 0;
	// state = 1 if this slot stored some data that were deleted; otherwise state = 0
	private byte[][] authenticationPath = null; 
	// authentication path from the bottom to the root; the
	// bottom node lies at the beginning of the array

	public MetaProofData(int index,  byte[] filename, int state, byte[][] authenticationPath) {
		super();
		this.index = index;
		this.filename = filename;
		this.state = state;
		this.authenticationPath = authenticationPath;
	}

	public MetaProofData(int index, byte[] filename, int state) {
		super();
		this.index = index;
		this.filename = filename;
		this.state = state;
		this.authenticationPath = null;
	}

	public byte[] generateHash() {
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("SHA-256");
		} catch (Exception e) {
			System.out.println("get SHA-256 instance error - static verify");
			System.out.println(e);
		}

		md.update(int2byteArray(this.index));
		md.update(this.filename);	
		return md.digest(int2byteArray(this.state));	
	}
	
	/**
	 * This function check whether an authentication path is legal. A legal path has
	 * two properties: one is that the leaf node value is equal to hash(index,
	 * filename); the other is that the authentication path is correct.
	 * 
	 * @param root - the root value of the hash authentication tree
	 * @return true/false
	 */
	public boolean validate(byte[] root) {
		int cheatFlag = 0;

		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("SHA-256");
		} catch (Exception e) {
			System.out.println("get SHA-256 instance error - static verify");
			System.out.println(e);
		}

		md.update(int2byteArray(this.index));
		md.update(this.filename);	
		byte[] tempMac = md.digest(int2byteArray(this.state));

		// check the leaf node value
		if (Arrays.equals(tempMac, this.authenticationPath[0]) == false
				&& Arrays.equals(tempMac, this.authenticationPath[1]) == false)
			cheatFlag = cheatFlag + 1;

		// check the authentication path
		if (HashTree.verify(authenticationPath, root) == false)
			cheatFlag = cheatFlag + 1;
		
		if (cheatFlag == 0)
			return true;
		else
			return false;
	}	
	
	private byte[] int2byteArray(int num) {
		byte[] result = new byte[4];

		result[3] = (byte) (num >>> 24);
		result[2] = (byte) (num >>> 16);
		result[1] = (byte) (num >>> 8);
		result[0] = (byte) (num);

		return result;
	}

	/**
	 * This function prints out the proof data object.
	 */
	public void print() {
		String temp = "[ ";
		temp = temp + String.valueOf(this.index) + "; ";
		temp = temp + DynamicVFS.bytes2HexString(this.filename) + "; ";
		temp = temp + String.valueOf(this.state) + "; ";

		for (int i = 0; i < this.authenticationPath.length; i++)
			temp = temp + DynamicVFS.bytes2HexString(this.authenticationPath[i]) + " ";
		temp = temp + "]";
		System.out.println(temp);
	}

	public int getIndex() {
		return index;
	}

	public void setIndex(int index) {
		this.index = index;
	}

	public byte[] getFilename() {
		return filename;
	}

	public void setFilename(byte[] filename) {
		this.filename = filename;
	}
	
	public int getState() {
		return state;
	}

	public void setState(int state) {
		this.state = state;
	}

	public byte[][] getAuthenticationPath() {
		return authenticationPath;
	}

	public void setAuthenticationPath(byte[][] authenticationPath) {
		this.authenticationPath = authenticationPath;
	}

}
