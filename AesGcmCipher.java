/*
 * Copyright (c) 2021 GEMALTO. All Rights Reserved.
 *
 * This software is the confidential and proprietary information of GEMALTO.
 *
 * -----------------------------------------------------------------------------
 * GEMALTO MAKES NO REPRESENTATIONS OR WARRANTIES ABOUT THE SUITABILITY OF
 * THE SOFTWARE, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 * PURPOSE OR NON-INFRINGEMENT. GEMALTO SHALL NOT BE LIABLE FOR ANY
 * DAMAGES SUFFERED BY LICENSEE AS A RESULT OF USING, MODIFYING OR
 * DISTRIBUTING THIS SOFTWARE OR ITS DERIVATIVES.
 *
 * THIS SOFTWARE IS NOT DESIGNED OR INTENDED FOR USE OR RESALE AS ON-LINE
 * CONTROL EQUIPMENT IN HAZARDOUS ENVIRONMENTS REQUIRING FAIL-SAFE
 * PERFORMANCE, SUCH AS IN THE OPERATION OF NUCLEAR FACILITIES, AIRCRAFT
 * NAVIGATION OR COMMUNICATION SYSTEMS, AIR TRAFFIC CONTROL, DIRECT LIFE
 * SUPPORT MACHINES, OR WEAPONS SYSTEMS, IN WHICH THE FAILURE OF THE
 * SOFTWARE COULD LEAD DIRECTLY TO DEATH, PERSONAL INJURY, OR SEVERE
 * PHYSICAL OR ENVIRONMENTAL DAMAGE ("HIGH RISK ACTIVITIES"). GEMALTO
 * SPECIFICALLY DISCLAIMS ANY EXPRESS OR IMPLIED WARRANTY OF FITNESS FOR
 * HIGH RISK ACTIVITIES.
 */

package com.gemalto.tkm.tests.utils;

import java.io.*;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.gemalto.tkm.common.util.HexString;
import com.gemalto.tkm.tests.annotations.TestUtility;

/**
 * Utility to cipher / uncipher data with an AES key.
 * Cipher / decipher algo is AES/GCM/NoPadding.
 **/

@TestUtility(comment = "Utility class, for Galois Counter Mode algorithm (AES/GCM/NoPadding)")
public final class AesGcmCipher {

    private AesGcmCipher() {
    }

    /**
     * Cipher data using GCM.
     *
     * @param iv         value of the initial vector
     * @param keyValue   value of the key used in the process
     * @param data       to cipher
     * @param authentTagLenthInBits  authentication tag length in bits
     * @param aad additional authenticated data (can be null)
     * @return array of bytes containing ciphered data (the iv vector is not present)
     * @throws Exception should an exception occur
     **/
    public static byte[] cipherData(final byte[] iv, final byte[] keyValue, final byte[] data, final int authentTagLenthInBits, final byte[] aad) throws Exception {

        if (iv == null || iv.length != 12) {
            throw new IllegalArgumentException("Bad IV length : " + HexString.fromBytes(iv));
        }

        if (keyValue == null || keyValue.length < 1) {
            throw new IllegalArgumentException("No cipher key defined");
        }

        if ( authentTagLenthInBits <= 0 ) {
            throw new IllegalArgumentException("AuthenticationTagLenthInBits <= 0" );
        }

        final SecretKey secretKey;
        try {
            secretKey = new SecretKeySpec(keyValue, "AES");
        } catch (final Exception e) {
            throw new IllegalArgumentException("Unable to parse key : " + HexString.fromBytes(keyValue) + ":" + e);
        }

        Cipher cipher = Cipher.getInstance( "AES/GCM/NoPadding" );
        GCMParameterSpec parameterSpec = new GCMParameterSpec( authentTagLenthInBits, iv );
        cipher.init( Cipher.ENCRYPT_MODE, secretKey, parameterSpec );
        if( aad != null ) {
            cipher.updateAAD( aad );
        }
        byte[] cipheredData = null;
        if (data == null){
            cipheredData =  cipher.doFinal();
        }
        else {
            cipheredData = cipher.doFinal(data);
        }
        return cipheredData;
    }

    /**
     * Uncipher data using AES/GCM/NoPadding algorithm
     *
     * @param iv         value of the initial vector
     * @param keyValue   value of the key used in the process
     * @param data       to uncipher
     * @param authentTagLenthInBits  authentication tag length in bits
     * @param aad additional authenticated data (can be null)
     * @return
     * @throws Exception thrown in case an exception occured
     */

    public static byte[] uncipherData(final byte[] iv, final byte[] keyValue, final byte[] data, final int authentTagLenthInBits, final byte[] aad) throws Exception {

        if (iv == null || iv.length != 12) {
            throw new IllegalArgumentException("Bad IV length : " + HexString.fromBytes(iv));
        }

        if (keyValue == null || keyValue.length < 1) {
            throw new IllegalArgumentException("No uncipher key defined");
        }

        if (data == null || data.length < 1) {
            throw new IllegalArgumentException("No data to uncypher");
        }

        if ( authentTagLenthInBits <= 0 ) {
            throw new IllegalArgumentException("AuthenticationTagLenthInBits <= 0" );
        }

        final SecretKey secretKey;
        try {
            secretKey = new SecretKeySpec(keyValue, "AES");
        } catch (final Exception e) {
            throw new IllegalArgumentException("Unable to parse key : " + HexString.fromBytes(keyValue) + ":" + e, e);
        }

        Cipher cipher = Cipher.getInstance( "AES/GCM/NoPadding" );
        GCMParameterSpec parameterSpec = new GCMParameterSpec( authentTagLenthInBits, iv );
        cipher.init( Cipher.DECRYPT_MODE, secretKey, parameterSpec );
        if( aad != null ) {
            cipher.updateAAD( aad );
        }

        final byte[] clearData = cipher.doFinal( data );
        return clearData;
    }

    /**
     * Cipher file using the "AES/GCM/NoPadding" algorithm.
     *
     * @param iv       value of the initial vector
     * @param keyValue value of the key used in the process
     * @param data     data to cipher
     * @param securityItem security item name
     * @param authentTagLenthInBits  authentication tag length in bits
     * @param aad additional authenticated data (can be null)
     * @return file of bytes containing the IV Vector bytes and then the ciphered data
     * @throws Exception should an exception occur
     **/
    public static File cipherFile(final byte[] iv, final byte[] keyValue, final InputStream data, final int authentTagLenthInBits, final byte[] aad,String securityItem) throws Exception {
        return cipherFile(iv, keyValue, data,authentTagLenthInBits,aad,securityItem,"AES/GCM/NoPadding");
    }


    /**
     * Cipher file using thespecified algorithm.
     *
     * @param iv         value of the initial vector
     * @param keyValue   value of the key used in the process
     * @param data       data to cipher
     * @param cypherAlgo cypher algo to use for cypher
     * @param securityItem security item name
     * @param authentTagLenthInBits  authentication tag length in bits
     * @param aad additional authenticated data (can be null)
     * @return file of bytes containing the IV Vector bytes followed by ciphered data
     * @throws Exception should an exception occur
     **/
    public static File cipherFile(final byte[] iv, final byte[] keyValue, final InputStream data, final int authentTagLenthInBits, final byte[] aad,String securityItem,String cypherAlgo) throws Exception {

        if (iv == null || iv.length != 12) {
            throw new IllegalArgumentException("Bad IV length : " + HexString.fromBytes(iv));
        }

        if (keyValue == null || keyValue.length < 1) {
            throw new IllegalArgumentException("No uncipher key defined");
        }

        if ( authentTagLenthInBits <= 0 ) {
            throw new IllegalArgumentException("AuthenticationTagLenthInBits <= 0" );
        }
        SecretKey secretKey = null;
        try {
            secretKey = new SecretKeySpec(keyValue, "AES");
        } catch (final Exception e) {
            throw new IllegalArgumentException("Unable to parse key : " + HexString.fromBytes(keyValue) + ":" + e);
        }
        PushbackInputStream pushbackInputStream = new PushbackInputStream(data);
        int b = pushbackInputStream.read();
        if (data == null || b ==-1) {
            throw new IllegalArgumentException("No data to cypher : " + HexString.fromBytes(iv));
        }
        pushbackInputStream.unread(b);
        Cipher cipher = Cipher.getInstance( "AES/GCM/NoPadding" );
        GCMParameterSpec parameterSpec = new GCMParameterSpec( authentTagLenthInBits, iv );
        cipher.init( Cipher.ENCRYPT_MODE, secretKey, parameterSpec );
        if( aad != null ) {
            cipher.updateAAD( aad );
        }
        String fileName = "cipher_file_"+securityItem;
        final File file = new File("src/test/resources/DEV/staticData/cipheredFiles",fileName+".txt");
        try (final FileOutputStream baos = new FileOutputStream(file)) {
            try (final BufferedInputStream bais = new BufferedInputStream(pushbackInputStream)) {
                baos.write(iv);
                long totalCipheredBytes = 0L;
                final byte[] buffer = new byte[8 * 1024]; // best size to have best HSM performance
                int bytesRead;
                while ((bytesRead = bais.read(buffer)) != -1) {
                    totalCipheredBytes += bytesRead;
                    final byte[] out = cipher.update(buffer, 0, bytesRead);
                    if (out != null) {
                        baos.write(out);
                    }
                }
                baos.write(cipher.doFinal());
            }
        }
        return file;
    }

    /**
     * Decipher file using the "AES/GCM/NoPadding" algorithm.
     *
     * @param iv       value of the initial vector
     * @param keyValue value of the key used in the process
     * @param data     data to cipher
     * @param securityItem security item name
     * @param authentTagLenthInBits  authentication tag length in bits
     * @param aad additional authenticated data (can be null)
     * @return file of bytes containing the IV Vector bytes and then the deciphered data
     * @throws Exception should an exception occur
     **/
    public static File decipherFile(final byte[] iv, final byte[] keyValue, final InputStream data, final int authentTagLenthInBits, final byte[] aad,String securityItem) throws Exception {
        return decipherFile(iv, keyValue, data,authentTagLenthInBits,aad,securityItem,"AES/GCM/NoPadding");
    }


    /**
     * Decipher file using thespecified algorithm.
     *
     * @param iv         value of the initial vector
     * @param keyValue   value of the key used in the process
     * @param data       data to cipher
     * @param cypherAlgo cypher algo to use for cypher
     * @param securityItem security item name
     * @param authentTagLenthInBits  authentication tag length in bits
     * @param aad additional authenticated data (can be null)
     * @return file of bytes containing the IV Vector bytes followed by deciphered data
     * @throws Exception should an exception occur
     **/
    public static File decipherFile(final byte[] iv, final byte[] keyValue, final InputStream data, final int authentTagLenthInBits, final byte[] aad,String securityItem,String cypherAlgo) throws Exception {

        if (iv == null || iv.length != 12) {
            throw new IllegalArgumentException("Bad IV length : " + HexString.fromBytes(iv));
        }

        if (keyValue == null || keyValue.length < 1) {
            throw new IllegalArgumentException("No uncipher key defined");
        }

        if ( authentTagLenthInBits <= 0 ) {
            throw new IllegalArgumentException("AuthenticationTagLenthInBits <= 0" );
        }

        SecretKey secretKey = null;
        try {
            secretKey = new SecretKeySpec(keyValue, "AES");
        } catch (final Exception e) {
            throw new IllegalArgumentException("Unable to parse key : " + HexString.fromBytes(keyValue) + ":" + e);
        }
        PushbackInputStream pushbackInputStream = new PushbackInputStream(data);
        int b = pushbackInputStream.read();
        if (data == null || b ==-1) {
            throw new IllegalArgumentException("No data to cypher : " + HexString.fromBytes(iv));
        }
        pushbackInputStream.unread(b);
        Cipher cipher = Cipher.getInstance( "AES/GCM/NoPadding" );
        GCMParameterSpec parameterSpec = new GCMParameterSpec( authentTagLenthInBits, iv );
        cipher.init( Cipher.DECRYPT_MODE, secretKey, parameterSpec );
        if( aad != null ) {
            cipher.updateAAD( aad );
        }
        String fileName = "decipher_file_"+securityItem;
        final File file = new File("src/test/resources/DEV/staticData/decipheredFiles",fileName+".txt");
        try (final FileOutputStream baos = new FileOutputStream(file)) {
            try (final BufferedInputStream bais = new BufferedInputStream(pushbackInputStream)) {
                baos.write(iv);
                long totalCipheredBytes = 0L;
                final byte[] buffer = new byte[8 * 1024]; // best size to have best HSM performance
                int bytesRead;
                while ((bytesRead = bais.read(buffer)) != -1) {
                    totalCipheredBytes += bytesRead;
                    final byte[] out = cipher.update(buffer, 0, bytesRead);
                    if (out != null) {
                        baos.write(out);
                    }
                }
                baos.write(cipher.doFinal());
            }
        }
        return file;
    }

}
