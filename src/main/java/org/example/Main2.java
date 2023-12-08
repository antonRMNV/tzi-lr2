package org.example;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import java.util.Base64;

public class Main2 {

    public static void main(String[] args) throws Exception {
        // Generate key pair
        KeyPair keyPair = generateKeyPair();

        // Original message
        String originalMessage = "qwerty123456";

        // Encrypt the message using the public key
        byte[] encryptedBytes = encrypt(originalMessage, keyPair.getPublic());

        // Decrypt the message using the private key
        String decryptedMessage = decrypt(encryptedBytes, keyPair.getPrivate());

        // Print results
        System.out.println("Original Message: " + originalMessage);
        System.out.println("Encrypted Message: " + Base64.getEncoder().encodeToString(encryptedBytes));
        System.out.println("Decrypted Message: " + decryptedMessage);
    }

    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); // You can adjust the key size as needed
        return keyPairGenerator.generateKeyPair();
    }

    private static byte[] encrypt(String input, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(input.getBytes());
    }

    private static String decrypt(byte[] encryptedBytes, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes);
    }
}
