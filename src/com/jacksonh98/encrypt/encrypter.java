package com.jacksonh98.encrypt;

import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;

public class encrypter implements ActionListener {
	
	private String 		
						AES = "AES/CBC/PKCS5Padding",
						keyFileLocation = "D:\\Documents\\Encryption test\\secretKey.key",
						actingOnFile = null,
						encryptExtension = ".encrypted",
						IvSpecString = null;
	
	private byte[] IvSpecByte;
	
	private int selectedFileType = -1;
	
	private static int TYPE_FILE = 1;
	private static int TYPE_DIR = 2;
	
	private IvParameterSpec ivspec = generateIV(false);
	private SecretKey privateKey; //Encryption key
	
	private JFrame frmEncrypter;
	private JTextField textField;
	public JButton btnDecrypt;
	public JButton btnEncrypt;
	public JButton btnFileSelector;
	JFileChooser JFChooser = new JFileChooser();
	FileExplorer fileExp = new FileExplorer();
	
	
	public static void main(String args[]) throws FileNotFoundException, NoSuchAlgorithmException, IOException {
		new encrypter(); 
	}
	
	public encrypter() throws FileNotFoundException, IOException, NoSuchAlgorithmException {
		File keyFile = new File(keyFileLocation);
		if(keyFile.exists()) {
			loadKeyFile(keyFileLocation);
			System.out.println("Loaded keyfile");
			}
		else {
			System.out.println("Could not find keyfile at " + keyFile.getAbsolutePath() + ", generating a new key...");
			privateKey = generateKey();
			saveKeyFile(keyFileLocation, privateKey);
		}
		
		initialize();
		
	}
	
	//Run cipher on a folder of items
	private boolean runOnFolder(int cipherMode) {
		
		File folder = new File(actingOnFile); //Folder location
		File[] folderContents = folder.listFiles(); //Load folder contents
		
		if(folderContents == null) {
			System.out.println("No files found");
			return false;
		}
		
		for(int i = 0; i < folderContents.length; i++) { //Loop contents of folder
			if(folderContents[i].exists() && folderContents[i].isFile()) { //Check it is a file
				actingOnFile = folderContents[i].getAbsolutePath(); //Store the path
				runCipher(cipherMode); // Run the cipher
			}
		}
		
		return true;
	}
	
	//Encrypt or decrypt the file using specified cipher
	private boolean runCipher(int cipherMode) {
		
		try {
			File fileTarget = new File(actingOnFile); //Target file to encrypt or decrypt
			Cipher ci = Cipher.getInstance(AES); //Use AES
			ci.init(cipherMode, privateKey, ivspec); //Initiate cipher
			processFile(ci, fileTarget, cipherMode); //Process file with cipher
			return true;
			} catch (Exception e) {
				e.printStackTrace();
			}
		return false;
	}
	
	//Generates an AES key
	private SecretKey generateKey() throws NoSuchAlgorithmException {
		KeyGenerator kgen = KeyGenerator.getInstance("AES");
		SecretKey skey = kgen.generateKey();
		return skey;
	}
	
	//Loads AES key file
	private boolean loadKeyFile(String keyLocation) throws IOException {
		byte[] keyb = Files.readAllBytes(Paths.get(keyLocation));
		privateKey = new SecretKeySpec(keyb, "AES");
		return true;
	}
	
	private boolean saveKeyFile(String keyLocation, SecretKey skey) throws FileNotFoundException, IOException {
		try (FileOutputStream out = new FileOutputStream(keyLocation)) {
		    byte[] keyb = skey.getEncoded();
		    out.write(keyb);
		}
		return false;
	}
	
	public boolean processFile(Cipher cipher, File inFile, int cipherMode) {
		
		File outFile = null;
		
		if(cipherMode == Cipher.DECRYPT_MODE) {
			
			if(!inFile.getAbsolutePath().contains(encryptExtension)) {
				System.out.println("File is not encrypted!");
				return false;
			}
			String outputString = inFile.getAbsolutePath().replace(encryptExtension, "");
			outFile = new File(outputString);
			inFile = new File(inFile.getAbsolutePath());
		}
		else if(cipherMode == Cipher.ENCRYPT_MODE) {
			
			if(inFile.getAbsolutePath().contains(encryptExtension)) {
				System.out.println("File is encrypted!");
				return false;
			}
			
			 //Add .encrypted to the encrypted file
			outFile = new File(inFile.getAbsolutePath()+encryptExtension); 
			inFile = new File(inFile.getAbsolutePath());
		}
		
		System.out.println("Input: " + inFile.getAbsolutePath());
		System.out.println("Output: " + outFile.getAbsolutePath());

		try (FileInputStream in = new FileInputStream(inFile);
	             FileOutputStream out = new FileOutputStream(outFile)) {
	            byte[] ibuf = new byte[8192];
	            int len;
	            while ((len = in.read(ibuf)) != -1) {
	                byte[] obuf = cipher.update(ibuf, 0, len);
	                if ( obuf != null ) out.write(obuf);
	            }
	            byte[] obuf = cipher.doFinal();
	            if ( obuf != null ) {
	            	out.write(obuf);
	            }
	            return true;
	        }
		
		catch (Exception ex) { 
			ex.printStackTrace();
		}
		return false;
		
	}
	
	//Generate an IV - should always be true for random
	public IvParameterSpec generateIV(boolean random) {
		byte[] bIvSpec = new byte[16];
		if(random) {
			SecureRandom randomValue = new SecureRandom();
			randomValue.nextBytes(bIvSpec);
		}
		else for(byte i = 0; i < bIvSpec.length; i++) bIvSpec[i] = i; //Simple IV for testing
		
		IvSpecByte = bIvSpec;
		IvParameterSpec ivspec = new IvParameterSpec(bIvSpec);
		return ivspec;
	}

	@Override
	public void actionPerformed(ActionEvent ae) {
		Object source = ae.getSource();
		
		if(source == btnEncrypt) {
			if(selectedFileType == TYPE_DIR) {
				runOnFolder(Cipher.ENCRYPT_MODE);
			}
			else if(selectedFileType == TYPE_FILE) {
				runCipher(Cipher.ENCRYPT_MODE);
			}
		} 
		else if(source == btnDecrypt) {
			if(selectedFileType == TYPE_DIR) {
				runOnFolder(Cipher.DECRYPT_MODE);
			} else if(selectedFileType == TYPE_FILE) {
				runCipher(Cipher.DECRYPT_MODE);
			}
		}
		else if(source == btnFileSelector) {
			int returnVal = JFChooser.showOpenDialog(fileExp); //Opens file chooser window
			
			if (returnVal == JFileChooser.APPROVE_OPTION) { //File or folder chosen
				File fSelectedFile = JFChooser.getSelectedFile();
	            actingOnFile = fSelectedFile.getAbsolutePath(); //Store the path for later use
	            textField.setText(actingOnFile); 
	            
	            //Store the type
	            if(fSelectedFile.isFile()) selectedFileType = TYPE_FILE;
	            else if(fSelectedFile.isDirectory()) selectedFileType = TYPE_DIR;
	            else selectedFileType = -1;
	            
	        } else {
	        	System.out.println("No file opened.");
	        }
		}
		
	}
	
	//GUI window
	private void initialize() {
		frmEncrypter = new JFrame();
		frmEncrypter.setTitle("Encrypter");
		frmEncrypter.setBounds(100, 100, 450, 300);
		frmEncrypter.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frmEncrypter.getContentPane().setLayout(new BoxLayout(frmEncrypter.getContentPane(), BoxLayout.X_AXIS));
		
		JPanel panel = new JPanel();
		frmEncrypter.getContentPane().add(panel);
		panel.setLayout(new GridLayout(0, 1, 0, 0));
		
		JLabel lblSelectAFile = new JLabel("Select a file or folder to act on:");
		panel.add(lblSelectAFile);
		
		textField = new JTextField();
		panel.add(textField);
		textField.setColumns(10);
		
		btnFileSelector = new JButton("Select file(s)...");
		panel.add(btnFileSelector);
		
		JLabel lbFilesDisplay = new JLabel("Files selected:");
		panel.add(lbFilesDisplay);
		
		JLabel lbFoldersDisplay = new JLabel("Folders selected:");
		panel.add(lbFoldersDisplay);
		
		btnEncrypt = new JButton("Encrypt");
		panel.add(btnEncrypt);
		
		btnDecrypt = new JButton("Decrypt");
		panel.add(btnDecrypt);
		
		btnEncrypt.addActionListener(this);
		btnFileSelector.addActionListener(this);
		btnDecrypt.addActionListener(this);
		
		frmEncrypter.setVisible(true);
		JFChooser.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);
	}
	
}

//File chooser stub
class FileExplorer extends JFileChooser {
	private static final long serialVersionUID = 1L;
	
	public FileExplorer() {
		
	}
}

	