package com.nadir;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import com.nadir.algorithms.CalculTime;
import com.nadir.algorithms.RSA;

public class App {
    public static void main(String[] args) throws Exception{
        CalculTime c = new CalculTime();
        
        c.CalculTimeProcess(()->{
            try {
                sinarioRSA();
            } catch (Exception e) {
            }
            return new Object();
        });
        //sinarioRSA();
        

    }

    public static void sinarioRSA() throws Exception{
        String message = "secret message";
        RSA rsa = new RSA();
        
        //la partie serveur genere ses propres clés
        KeyPair serverKeyPair = rsa.generateKeyPair();
        PrivateKey serverPrivateKey = serverKeyPair.getPrivate();
        PublicKey serverPublicKey = serverKeyPair.getPublic();

        //la partie client genere ses propres clés
        KeyPair clientKeyPair = rsa.generateKeyPair();
        PrivateKey clientPrivateKey = clientKeyPair.getPrivate();
        PublicKey clientPublicKey = clientKeyPair.getPublic();

        String encodedServerPublicKey = Base64.getEncoder().encodeToString(serverPublicKey.getEncoded());
        String encodedClientPublicKey = Base64.getEncoder().encodeToString(clientPublicKey.getEncoded());

        //1. Serveur reçoit la clé publique du client encoder dans la base 64
        PublicKey decodedClientPublicKey = rsa.readPublicKeyFromBase64(encodedClientPublicKey);
        String encryptedMessage = rsa.encrypt(message, decodedClientPublicKey);
        String signature = rsa.sign(encryptedMessage, serverPrivateKey);

        //2. serveur envoie du 'encryptedMessage', 'signature', 'EncodedServerPublicKey'
        PublicKey decodedServerPublicKey = rsa.readPublicKeyFromBase64(encodedServerPublicKey);
        boolean verification = rsa.verificationSign(encryptedMessage, signature, decodedServerPublicKey);
        if(!verification){
            String receivedMessage = rsa.decrypt(encryptedMessage, clientPrivateKey);
            System.out.println("un message est reçu : "+receivedMessage);
        }else{
            System.out.println("Erreur: la signature n'est pas verifié");
        }
    }
}
