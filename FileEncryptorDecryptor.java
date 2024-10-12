/**
 * FileEncryptorDecryptor
 * 
 * This is a Java Swing-based GUI application for encrypting and decrypting files
 * using AES encryption in CBC (Cipher Block Chaining) mode with PKCS5 padding.
 * The user can input a file, along with a hexadecimal key and initialization vector (IV).
 * The encrypted file is saved with a `.sidenc` extension, and a `.params` file is generated
 * to store the encryption key and IV. The application also allows decryption of `.sidenc` files.
 * 
 * Features:
 * - Allows the user to select a file for encryption or decryption.
 * - Takes a user-provided AES key and IV in hexadecimal format.
 * - Saves encrypted files with a `.sidenc` extension.
 * - Saves the key and IV in a `.params` file, which is stored in the same directory as the selected file.
 * - Decrypts `.sidenc` files to restore the original file format.
 * 
 * Main components:
 * - JTextField for inputting the AES key (hex).
 * - JTextField for inputting the IV (hex).
 * - JFileChooser for selecting the file to encrypt or decrypt.
 * - JButton to trigger encryption or decryption.
 * - Encryption and decryption logic using AES/CBC/PKCS5Padding.
 * 
 * Usage:
 * - Select a file via the "Select File" button.
 * - Enter the encryption key (hex) and IV (hex).
 * - Click "Encrypt" to generate the encrypted file and save the key and IV in a `.params` file.
 * - Click "Decrypt" to decrypt an encrypted `.sidenc` file.
 * 
 * Notes:
 * - The `.params` file is saved with the same base name as the selected file (e.g., `document.params`)
 *   and is stored in the same directory as the file.
 * - The AES encryption key must be 16, 24, or 32 bytes long (128, 192, or 256 bits).
 * - The IV must be 16 bytes long (128 bits).
 * 
 * Example:
 * - Original file: `document.txt`
 * - Encrypted file: `document.txt.sidenc`
 * - Parameters file: `document.params`
 * - Decrypted file (restored to original): `document.txt`
 * 
 * How to run:
 * - Compile the program: javac FileEncryptor.java
 * - Package it as a runnable JAR: jar cfe FileEncryptorApp.jar FileEncryptor *.class
 * - Run the JAR file: java -jar FileEncryptorApp.jar
 * 
 * Dependencies:
 * - None (pure Java).
 * 
 * Author: Siddharth Bej
 * Date: October 2024
 */

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.nio.file.Files;
import java.security.Key;
import java.util.Base64;

public class FileEncryptorDecryptor extends JFrame {
    private JTextField keyField;
    private JTextField ivField;
    private JButton selectFileButton;
    private JButton encryptButton;
    private JButton decryptButton;
    private File selectedFile;

    public FileEncryptorDecryptor() {
        // GUI Setup
        setTitle("File Encryptor & Decryptor | X3n0Sidd1337");
        setSize(420, 180);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(null);

        JLabel keyLabel = new JLabel("Key (Hex):");
        keyLabel.setBounds(20, 20, 80, 25);
        add(keyLabel);

        keyField = new JTextField();
        keyField.setBounds(100, 20, 200, 25);
        add(keyField);

        JLabel ivLabel = new JLabel("IV (Hex):");
        ivLabel.setBounds(20, 60, 80, 25);
        add(ivLabel);

        ivField = new JTextField();
        ivField.setBounds(100, 60, 200, 25);
        add(ivField);

        selectFileButton = new JButton("Select File");
        selectFileButton.setBounds(20, 100, 120, 25);
        add(selectFileButton);

        encryptButton = new JButton("Encrypt");
        encryptButton.setBounds(150, 100, 100, 25);
        add(encryptButton);

        decryptButton = new JButton("Decrypt");
        decryptButton.setBounds(260, 100, 100, 25);
        add(decryptButton);

        // Action Listeners
        selectFileButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JFileChooser fileChooser = new JFileChooser();
                int result = fileChooser.showOpenDialog(null);
                if (result == JFileChooser.APPROVE_OPTION) {
                    selectedFile = fileChooser.getSelectedFile();
                    JOptionPane.showMessageDialog(null, "Selected file: " + selectedFile.getAbsolutePath());
                }
            }
        });

        encryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (selectedFile != null) {
                    try {
                        encryptFile(selectedFile, keyField.getText(), ivField.getText());
                        JOptionPane.showMessageDialog(null, "File encrypted successfully!");
                    } catch (Exception ex) {
                        JOptionPane.showMessageDialog(null, "Encryption failed: " + ex.getMessage());
                    }
                } else {
                    JOptionPane.showMessageDialog(null, "No file selected.");
                }
            }
        });

        decryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (selectedFile != null) {
                    try {
                        decryptFile(selectedFile, keyField.getText(), ivField.getText());
                        JOptionPane.showMessageDialog(null, "File decrypted successfully!");
                    } catch (Exception ex) {
                        JOptionPane.showMessageDialog(null, "Decryption failed: " + ex.getMessage());
                    }
                } else {
                    JOptionPane.showMessageDialog(null, "No file selected.");
                }
            }
        });
    }

    // Method to save key and IV in a .parms file (in the same directory as the selected file)
    private void saveKeyAndIV(String keyHex, String ivHex, File inputFile) throws IOException {
        // Get the directory and filename of the input file
        String filePath = inputFile.getParent();
        String fileName = inputFile.getName();
        
        // Remove the file extension
        String baseName = fileName.contains(".") ? fileName.substring(0, fileName.lastIndexOf('.')) : fileName;

        // Create the .parms file in the same directory with the same base name
        File parmsFile = new File(filePath, baseName + ".params");
        
        FileWriter writer = new FileWriter(parmsFile);
        writer.write("Key=" + keyHex + "\n");
        writer.write("IV=" + ivHex + "\n");
        writer.close();
    }

    // AES encryption method
    private void encryptFile(File inputFile, String keyHex, String ivHex) throws Exception {
        byte[] keyBytes = hexStringToByteArray(keyHex);
        byte[] ivBytes = hexStringToByteArray(ivHex);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        Key secretKey = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

        byte[] inputBytes = Files.readAllBytes(inputFile.toPath());
        byte[] outputBytes = cipher.doFinal(inputBytes);

        // Save the encrypted file with the .sidenc extension in the same directory
        FileOutputStream fos = new FileOutputStream(inputFile.getAbsolutePath() + ".sidenc");
        fos.write(outputBytes);
        fos.close();

        // Save the Key and IV to a .parms file (in the same directory)
        saveKeyAndIV(keyHex, ivHex, inputFile);
    }

    // AES decryption method
    private void decryptFile(File inputFile, String keyHex, String ivHex) throws Exception {
        byte[] keyBytes = hexStringToByteArray(keyHex);
        byte[] ivBytes = hexStringToByteArray(ivHex);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        Key secretKey = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

        byte[] inputBytes = Files.readAllBytes(inputFile.toPath());
        byte[] outputBytes = cipher.doFinal(inputBytes);

        // Save the decrypted file without the .sidenc extension
        FileOutputStream fos = new FileOutputStream(inputFile.getAbsolutePath().replace(".sidenc", ""));
        fos.write(outputBytes);
        fos.close();
    }

    // Utility method to convert Hex String to Byte Array
    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                FileEncryptorDecryptor encryptorDecryptor = new FileEncryptorDecryptor();
                encryptorDecryptor.setVisible(true);
            }
        });
    }
}
