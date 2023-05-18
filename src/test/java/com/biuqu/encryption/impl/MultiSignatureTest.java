package com.biuqu.encryption.impl;

import com.biuqu.encryption.MultiSignature;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.UUID;

public class MultiSignatureTest
{
    @Test
    public void testGm()
    {
        MultiSignature<KeyPair> gmEncryption = new GmEncryption();
        testEnc(gmEncryption);
        testSign(gmEncryption);
    }

    @Test
    public void testUs()
    {
        MultiSignature<KeyPair> usEncryption = new UsEncryption();
        testEnc(usEncryption);
        testSign(usEncryption);
    }

    private void testEnc(MultiSignature<KeyPair> encryption)
    {
        KeyPair keyPair1 = encryption.createKey(UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8));
        //创建加密端的密钥对1
        byte[] pri1 = keyPair1.getPrivate().getEncoded();
        byte[] pub1 = keyPair1.getPublic().getEncoded();
        System.out.println("pri1=" + Hex.toHexString(pri1));
        System.out.println("pub1=" + Hex.toHexString(pub1));

        //2.创建解密端的密钥对2
        KeyPair keyPair2 = encryption.createKey(UUID.randomUUID().toString().getBytes());
        byte[] pri2 = keyPair2.getPrivate().getEncoded();
        byte[] pub2 = keyPair2.getPublic().getEncoded();
        System.out.println("pri2=" + Hex.toHexString(pri2));
        System.out.println("pub2=" + Hex.toHexString(pub2));

        String text = "A very very good day.";

        //3.加密端加密后的密文
        byte[] encBytes = encryption.encrypt(text.getBytes(StandardCharsets.UTF_8), pri1, pub2);
        System.out.println("encBytes=" + new String(encBytes, StandardCharsets.UTF_8));

        byte[] decBytes = encryption.decrypt(encBytes, pub1, pri2);
        System.out.println("decBytes=" + new String(decBytes, StandardCharsets.UTF_8));
    }

    private void testSign(MultiSignature<KeyPair> encryption)
    {
        KeyPair keyPair1 = encryption.createKey(UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8));
        //创建加密端的密钥对
        byte[] pri1 = keyPair1.getPrivate().getEncoded();
        byte[] pub1 = keyPair1.getPublic().getEncoded();

        KeyPair keyPair2 = encryption.createKey(UUID.randomUUID().toString().getBytes());
        byte[] pri2 = keyPair2.getPrivate().getEncoded();
        byte[] pub2 = keyPair2.getPublic().getEncoded();

        System.out.println("pri1=" + Hex.toHexString(pri1));
        System.out.println("pub1=" + Hex.toHexString(pub1));

        String text = "A very very good day2.";
        byte[] dataBytes = text.getBytes(StandardCharsets.UTF_8);
        byte[] signBytes = encryption.sign(dataBytes, pri1, pub2);
        System.out.println("signBytes=" + Hex.toHexString(signBytes));

        boolean result = encryption.verify(signBytes, pub1, pri2);
        System.out.println("result=" + result);
    }
}