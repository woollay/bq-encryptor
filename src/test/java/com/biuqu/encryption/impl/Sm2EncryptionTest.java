package com.biuqu.encryption.impl;

import com.biuqu.encryption.BaseSingleSignature;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.UUID;

public class Sm2EncryptionTest
{

    @Test
    public void encrypt()
    {
        String text = "testTextAbc`123";
        BaseSingleSignature sm2 = new Sm2Encryption();
        KeyPair keyPair = sm2.createKey("test123".getBytes(StandardCharsets.UTF_8));
        byte[] pubKey = keyPair.getPublic().getEncoded();
        byte[] priKey = keyPair.getPrivate().getEncoded();

        byte[] encryptBytes = sm2.encrypt(text.getBytes(StandardCharsets.UTF_8), pubKey, null);
        byte[] decryptBytes = sm2.decrypt(encryptBytes, priKey, null);
        System.out.println("Decrypt text=" + new String(decryptBytes, StandardCharsets.UTF_8));
        Assert.assertTrue(text.equals(new String(decryptBytes, StandardCharsets.UTF_8)));
    }

    @Test
    public void encrypt2()
    {
        BaseSingleSignature sm2 = new Sm2Encryption();
        KeyPair keyPair = sm2.createKey("test123".getBytes(StandardCharsets.UTF_8));
        byte[] priKey0 = keyPair.getPrivate().getEncoded();
        byte[] pubKey0 = keyPair.getPublic().getEncoded();

        byte[] pubKey1 = ((BCECPublicKey)keyPair.getPublic()).getQ().getEncoded(false);
        byte[] pubKey2 = ((BCECPublicKey)keyPair.getPublic()).getQ().getEncoded(true);

        byte[] priKey1 = ((BCECPrivateKey)keyPair.getPrivate()).getD().toByteArray();
        System.out.println("standard priKey[" + priKey0.length + "]=" + Hex.toHexString(priKey0));
        System.out.println("sm2 priKey[" + priKey1.length + "]=" + Hex.toHexString(priKey1));
        System.out.println("*****************************************************************************");
        System.out.println("standard pubKey[" + pubKey0.length + "]=" + Hex.toHexString(pubKey0));
        System.out.println("uncompressed pubKey[" + pubKey1.length + "]=" + Hex.toHexString(pubKey1));
        System.out.println("compressed pubKey[" + pubKey2.length + "]=" + Hex.toHexString(pubKey2));
    }

    @Test
    public void encrypt3()
    {
        BaseSingleSignature sm2 = new Sm2Encryption();
        KeyPair keyPair = sm2.createKey(UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8));
        byte[] priKey0 = keyPair.getPrivate().getEncoded();
        byte[] pubKey0 = keyPair.getPublic().getEncoded();

        byte[] priKey1 = ((BCECPrivateKey)keyPair.getPrivate()).getD().toByteArray();
        byte[] pubKey1 = ((BCECPublicKey)keyPair.getPublic()).getQ().getEncoded(false);
        byte[] pubKey2 = ((BCECPublicKey)keyPair.getPublic()).getQ().getEncoded(true);
        System.out.println("standard priKey[" + priKey0.length + "]=" + Hex.toHexString(priKey0));
        System.out.println("$sm2 priKey[" + priKey1.length + "]=" + Hex.toHexString(priKey1));
        System.out.println("*****************************************************************************");
        System.out.println("standard pubKey[" + pubKey0.length + "]=" + Hex.toHexString(pubKey0));
        System.out.println("$uncompressed pubKey[" + pubKey1.length + "]=" + Hex.toHexString(pubKey1));
        System.out.println("$compressed pubKey[" + pubKey2.length + "]=" + Hex.toHexString(pubKey2));
        System.out.println("*****************************************************************************");

        String text = UUID.randomUUID().toString();
        byte[] encBytes = sm2.encrypt(text.getBytes(), pubKey2, null);
        byte[] decBytes = sm2.decrypt(encBytes, priKey0, null);
        String decText = new String(decBytes);
        System.out.println("text=" + text + ", and dec text=" + decText);

        byte[] encBytes2 = sm2.encrypt(text.getBytes(), pubKey1, null);
        byte[] decBytes2 = sm2.decrypt(encBytes2, priKey0, null);
        String decText2 = new String(decBytes2);
        System.out.println("text=" + text + ", and dec text=" + decText2);

        byte[] encBytes3 = sm2.encrypt(text.getBytes(), pubKey1, null);
        byte[] decBytes3 = sm2.decrypt(encBytes3, priKey1, null);
        String decText3 = new String(decBytes3);
        System.out.println("text=" + text + ", and dec text=" + decText3);
    }

    @Test
    public void decrypt()
    {
        String text = "testTextAbc`123";
        BaseSingleSignature sm2 = new Sm2Encryption();
        //C1C3C2 mode
        sm2.setPaddingMode("1");

        KeyPair keyPair = sm2.createKey("test123".getBytes(StandardCharsets.UTF_8));
        byte[] pubKey = keyPair.getPublic().getEncoded();
        byte[] priKey = keyPair.getPrivate().getEncoded();

        byte[] encryptBytes = sm2.encrypt(text.getBytes(StandardCharsets.UTF_8), pubKey, null);
        byte[] decryptBytes = sm2.decrypt(encryptBytes, priKey, null);
        System.out.println("Decrypt text=" + new String(decryptBytes, StandardCharsets.UTF_8));
        Assert.assertTrue(text.equals(new String(decryptBytes, StandardCharsets.UTF_8)));
    }

    @Test
    public void createKey()
    {
        BaseSingleSignature sm2 = new Sm2Encryption();
        KeyPair keyPair = sm2.createKey("test123".getBytes(StandardCharsets.UTF_8));
        System.out.println("priKey=" + Arrays.toString(keyPair.getPrivate().getEncoded()));
        System.out.println("pubKey=" + Arrays.toString(keyPair.getPublic().getEncoded()));
    }

    @Test
    public void signature()
    {
        String text = "testTextAbc`123";
        BaseSingleSignature sm2 = new Sm2Encryption();
        KeyPair keyPair = sm2.createKey("test123".getBytes(StandardCharsets.UTF_8));
        byte[] pubKey = keyPair.getPublic().getEncoded();
        byte[] priKey = keyPair.getPrivate().getEncoded();

        byte[] sign = sm2.sign(text.getBytes(StandardCharsets.UTF_8), priKey);
        boolean verifyResult = sm2.verify(text.getBytes(StandardCharsets.UTF_8), pubKey, sign);
        System.out.println("Verify Result=" + verifyResult);
        Assert.assertTrue(verifyResult);
    }

    @Test
    public void verifySign()
    {
        String text = "testTextAbc`123";
        BaseSingleSignature sm2 = new Sm2Encryption();
        //C1C3C2 mode
        sm2.setPaddingMode("1");

        KeyPair keyPair = sm2.createKey("test123".getBytes(StandardCharsets.UTF_8));
        byte[] pubKey = keyPair.getPublic().getEncoded();
        byte[] priKey = keyPair.getPrivate().getEncoded();

        byte[] sign = sm2.sign(text.getBytes(StandardCharsets.UTF_8), priKey);
        boolean verifyResult = sm2.verify(text.getBytes(StandardCharsets.UTF_8), pubKey, sign);
        System.out.println("Verify Result=" + verifyResult);
        Assert.assertTrue(verifyResult);
    }
}