package com.nadir.algorithms;

import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AesGcm {
    private final int AES_KEY_SIZE = 256;
    private final int GCM_IV_LENGTH = 12;
    private final int GCM_TAG_LENGTH = 16;
    private final String CIPHER_ALGO = "AES/GCM/NoPadding";
    private final String BASE_ALGO = "AES";
    private final byte[] IV;

    public AesGcm(){
        IV = generateInitVector();
    }

    public SecretKey generateSecretKey() throws Exception{
        KeyGenerator generator = KeyGenerator.getInstance(BASE_ALGO);
        generator.init(AES_KEY_SIZE);
        return generator.generateKey();
    }

    public SecretKey readKeyFromBase64(String keyBase64)throws Exception {
        byte[] decodedKey = Base64.getDecoder().decode(keyBase64);
        return new SecretKeySpec(decodedKey, BASE_ALGO);
    }

    public String encrypt(String text, SecretKey key)throws Exception{
        Cipher cipher = encryptionCipher(IV, key);
        cipher.update(text.getBytes());
        byte[] encryptText = cipher.doFinal();
        return Base64.getEncoder().encodeToString(encryptText);
    }

    public Cipher encryptionCipher(byte[] IV, SecretKey key) throws Exception{
        Cipher cipher = Cipher.getInstance(CIPHER_ALGO);
        SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), BASE_ALGO);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH*8, IV);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);
        return cipher;
    }

    public String decrypt(String encodedEncryptedText, SecretKey key) throws Exception{
        Cipher cipher = decryptionCipher(IV, key);
        byte[] encryptedText = Base64.getDecoder().decode(encodedEncryptedText);
        cipher.update(encryptedText);
        byte[] decryptText = cipher.doFinal();
        return new String(decryptText);
    }

    public Cipher decryptionCipher(byte[] IV, SecretKey key)throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGO);
        SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), BASE_ALGO);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH*8, IV);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec);
        return cipher;
    }

    public byte[] generateInitVector(){
        byte[] IV = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(IV);
        return IV;
    }
}
