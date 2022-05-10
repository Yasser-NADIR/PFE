package com.nadir;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import com.nadir.algorithms.RSA;

import org.junit.Before;
import org.junit.Test;

public class TestRSA 
{
    public RSA rsa = new RSA();
    
    public PublicKey publicKey;
    public PrivateKey privateKey;

    public String encodedPublicKey = "";
    public String encodedPrivateKey = "";

    public String secretMessage = "Hello there this is a secret message";

    @Before
    public void init() throws Exception{
        KeyPair keyPair = rsa.generateKeyPair();

        publicKey = keyPair.getPublic();
        privateKey = keyPair.getPrivate();

        encodedPublicKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        encodedPrivateKey = Base64.getEncoder().encodeToString(privateKey.getEncoded());
    }

    @Test
    public void verificationOfReadingPublicKeyFromBase64() throws Exception{
        PublicKey key = rsa.readPublicKeyFromBase64(encodedPublicKey);

        assertArrayEquals(publicKey.getEncoded(), key.getEncoded());
    }

    @Test
    public void verificationOfReadingPrivateKeyFromBase64() throws Exception{
        PrivateKey key = rsa.readPrivateKeyFromBase64(encodedPrivateKey);

        assertArrayEquals(privateKey.getEncoded(), key.getEncoded());
    }

    @Test
    public void verificationEncryptDecryptByPairKey() throws Exception{
        String encryptedMessage = rsa.encrypt(secretMessage, publicKey);
        String decryptedMessage = rsa.decrypt(encryptedMessage, privateKey);

        assertTrue(secretMessage.equals(decryptedMessage));
    }

    @Test
    public void verificationEncryptByCertificateDecryptByJKS() throws Exception{
        PublicKey publicKey = rsa.readPublicKeyFromCertificate("certificate.cert");
        PrivateKey privateKey = rsa.readPrivateKeyFromJKS("nadir.jks", "123456", "nadir");

        String encyptedMessage = rsa.encrypt(secretMessage, publicKey);
        String decryptedMessage = rsa.decrypt(encyptedMessage, privateKey);

        assertTrue(secretMessage.equals(decryptedMessage));
    }

    @Test
    public void verificationEncryptDecryptByKeyBase64() throws Exception{
        PublicKey publicKey = rsa.readPublicKeyFromBase64(encodedPublicKey);
        PrivateKey privateKey = rsa.readPrivateKeyFromBase64(encodedPrivateKey);

        String encyptedMessage = rsa.encrypt(secretMessage, publicKey);
        String decryptedMessage = rsa.decrypt(encyptedMessage, privateKey);

        assertTrue(secretMessage.equals(decryptedMessage));
    }

    @Test
    public void verificationOfSignature() throws Exception{
        String encryptedMessage = rsa.encrypt(secretMessage, publicKey);
        
        String signedMessage = rsa.sign(encryptedMessage, privateKey);

        assertTrue(rsa.verificationSign(encryptedMessage, signedMessage, publicKey));
    }

    @Test
    public void verificationofFalseSignature() throws Exception{
        String encryptedMessage = rsa.encrypt(secretMessage, publicKey);
        
        String signedMessage = rsa.sign(encryptedMessage, privateKey);
        String falseSignedMessage = "D"+signedMessage.substring(1);

        assertFalse(rsa.verificationSign(encryptedMessage, falseSignedMessage, publicKey));
    }

    @Test
    public void verificationModifiedMessage() throws Exception{
        String encryptedMessage = rsa.encrypt(secretMessage, publicKey);
        String signedMessage = rsa.sign(encryptedMessage, privateKey);

        String modifiedMessage = encryptedMessage+"dD";

        assertFalse(rsa.verificationSign(modifiedMessage, signedMessage, publicKey)); 
    }
}
