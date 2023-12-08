package org.example;

import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.util.encoders.Hex;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.Arrays;

public class Main1 {

    public static void main(String[] args) {
        String inputFirstMessage = readFromFile("matrix.txt");

        if (inputFirstMessage != null) {
            String hash = calculateSHAKE256(inputFirstMessage);
            System.out.println("Хеш: " + hash);

            long startTime = System.currentTimeMillis();
            long lastUpdateTime = startTime;
            int passwordsTried = 0;

            String recoveredPassword = bruteForce(hash, startTime, lastUpdateTime, passwordsTried);
            long endTime = System.currentTimeMillis();
            long runtime = endTime - startTime;

            System.out.println("Recovered Password: " + recoveredPassword);
            System.out.println("Runtime: " + runtime + " ms");
        }
    }

    public static String calculateSHAKE256(String input) {
        try {
            SHAKEDigest shake256Digest = new SHAKEDigest(256);
            byte[] inputBytes = input.getBytes("UTF-8");
            byte[] hashBytes = new byte[64];

            shake256Digest.update(inputBytes, 0, inputBytes.length);
            shake256Digest.doFinal(hashBytes, 0);

            return Hex.toHexString(hashBytes);
        } catch (java.io.UnsupportedEncodingException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String readFromFile(String fileName) {
        try {
            BufferedReader reader = new BufferedReader(new FileReader(fileName));
            StringBuilder stringBuilder = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                stringBuilder.append(line);
            }
            reader.close();
            return stringBuilder.toString();
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder(2 * bytes.length);
        for (byte b : bytes) {
            hexString.append(String.format("%02x", b & 0xff));
        }
        return hexString.toString();
    }

    public static String bruteForce(String targetHash, long startTime, long lastUpdateTime, int passwordsTried) {
        char[] charset = "abcdefghijklmnopqrstuvwxyz0123456789".toCharArray();
        int maxLength = 10;

        for (int len = 1; len <= maxLength; len++) {
            char[] password = new char[len];
            Arrays.fill(password, charset[0]);

            do {
                String passwordStr = new String(password);
                String hash = calculateSHAKE256(passwordStr);
                if (hash.equals(targetHash)) {
                    return passwordStr;
                }

                long currentTime = System.currentTimeMillis();
                if (currentTime - lastUpdateTime >= 5000) {
                    lastUpdateTime = currentTime;
                    long elapsedTime = currentTime - startTime;
                    System.out.println("З початку роботи програми пройшло: " + elapsedTime / 1000 + " секунд.");
                    System.out.println("Перебрано: " + (passwordsTried - (len - 1)) + " паролів");
                }

                passwordsTried++;

            } while (increment(password, charset));
        }

        return "Пароль не знайдено";
    }
    public static boolean increment(char[] password, char[] charset) {
        int index = password.length - 1;
        while (index >= 0) {
            char nextChar = charset[(Arrays.binarySearch(charset, password[index]) + 1) % charset.length];
            password[index] = nextChar;
            if (nextChar != charset[0]) {
                return true;
            }
            index--;
        }
        return false;
    }
}

