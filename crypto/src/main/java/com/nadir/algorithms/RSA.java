package com.nadir.algorithms;

import java.io.FileInputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

public class RSA {
    //générer une paire de clés
    public KeyPair generateKeyPair() throws Exception{
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");

        generator.initialize(1024);
        return generator.generateKeyPair();
    }

    //lire clé publique depuit la base64
    public PublicKey readPublicKeyFromBase64(String encodedPublicKey) throws Exception{
        KeyFactory factory = KeyFactory.getInstance("RSA");
        byte[] decodedPublicKey = Base64.getDecoder().decode(encodedPublicKey);
        PublicKey publicKey = factory.generatePublic(new X509EncodedKeySpec(decodedPublicKey));
        return publicKey;
    }

    //lire clé privée depuit la base64
    public PrivateKey readPrivateKeyFromBase64(String encodedPrivateKey) throws Exception{
        KeyFactory factory = KeyFactory.getInstance("RSA");
        byte[] decodedPrivateKey = Base64.getDecoder().decode(encodedPrivateKey);
        PrivateKey privateKey = factory.generatePrivate(new PKCS8EncodedKeySpec(decodedPrivateKey));
        return privateKey;
    }

    //lire clé publique depuit une certificat
    public PublicKey readPublicKeyFromCertificate(String certificateFilename) throws Exception{
        FileInputStream file = new FileInputStream(certificateFilename);
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        Certificate certificate = factory.generateCertificate(file);
        PublicKey publicKey = certificate.getPublicKey();
        return publicKey;
    }

    //lire clé privée depuit un fichier JKS
    public PrivateKey readPrivateKeyFromJKS(String JKSFilename, String password, String alias) throws Exception{
        FileInputStream file = new FileInputStream(JKSFilename);
        KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
        store.load(file, password.toCharArray());
        PrivateKey privateKey = (PrivateKey)store.getKey(alias, password.toCharArray());
        return privateKey;
    }

    //la fonction responsable de crypter
    public String encrypt(String text, PublicKey publicKey) throws Exception{
        Cipher cipher = encryptionCipher(publicKey);
        cipher.update(text.getBytes());
        byte[] encryptedText = cipher.doFinal();
        return Base64.getEncoder().encodeToString(encryptedText);
    }

    //la fonction responsable de décrypter
    public String decrypt(String encodedEncryptedText, PrivateKey privateKey) throws Exception{
        Cipher cipher = decryptionCipher(privateKey);
        byte[] EncryptedText = Base64.getDecoder().decode(encodedEncryptedText);
        cipher.update(EncryptedText);
        byte[] decryptedText = cipher.doFinal();
        return new String(decryptedText);
    }

    //création d'une cipher pour crypter
    public Cipher encryptionCipher(PublicKey publicKey) throws Exception{
        Cipher cipher = Cipher.getInstance("RSA");

        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher;
    }

    //création d'une cipher pour décrypter
    public Cipher decryptionCipher(PrivateKey privateKey)throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");

        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher;
    }

    //création d'une signature
    public String sign(String text, PrivateKey privateKey)throws Exception{
        Signature signature = Signature.getInstance("SHA256withRSA");

        signature.initSign(privateKey, new SecureRandom());
        signature.update(text.getBytes());
        byte[] signedText = signature.sign();
        return Base64.getEncoder().encodeToString(signedText);
    }

    //verification d'une signature
    public boolean verificationSign(String text, String EncodedSignedText, PublicKey publicKey)throws Exception{
        Signature signature = Signature.getInstance("SHA256withRSA");
        byte[] signedText = Base64.getDecoder().decode(EncodedSignedText);

        signature.initVerify(publicKey);
        signature.update(text.getBytes());
        return signature.verify(signedText);
    }


}
