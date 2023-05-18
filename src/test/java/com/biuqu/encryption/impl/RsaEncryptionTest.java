package com.biuqu.encryption.impl;

import com.biuqu.encryption.BaseSingleSignature;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;

public class RsaEncryptionTest
{
    @Test
    public void signature()
    {
        String initKey = "test RSA with initial key.";
        BaseSingleSignature encryption = new RsaEncryption();
        KeyPair keyPair = encryption.createKey(initKey.getBytes(StandardCharsets.UTF_8));

        byte[] priKey = keyPair.getPrivate().getEncoded();
        byte[] pubKey = keyPair.getPublic().getEncoded();
        byte[] signBytes = encryption.sign(initKey.getBytes(StandardCharsets.UTF_8), priKey);
        System.out.println("signBytes=" + Hex.toHexString(signBytes));
        boolean result = encryption.verify(initKey.getBytes(StandardCharsets.UTF_8), pubKey, signBytes);
        Assert.assertTrue(result);

        //替换SHA512WITHRSA签名算法为SHA256WITHRSA
        encryption.setSignatureAlg("SHA256WITHRSA");
        byte[] signBytes2 = encryption.sign(initKey.getBytes(StandardCharsets.UTF_8), priKey);
        System.out.println("signBytes2=" + Hex.toHexString(signBytes2));
        boolean result2 = encryption.verify(initKey.getBytes(StandardCharsets.UTF_8), pubKey, signBytes2);
        Assert.assertTrue(result2);
    }

    @Test
    public void createKey()
    {
        String initKey = "test RSA with initial key.";
        BaseSingleSignature encryption = new RsaEncryption();
        KeyPair keyPair = encryption.createKey(initKey.getBytes(StandardCharsets.UTF_8));

        byte[] priKey = keyPair.getPrivate().getEncoded();
        byte[] pubKey = keyPair.getPublic().getEncoded();

        String text = "test-RSA-with-text.";
        String text2 = text + text + text + text + text + text + text + text;
        text2 += text2;
        text2 += text2;
        text2 += text2;

        List<String> texts = new ArrayList<>();
        texts.add(text);
        texts.add(text2);
        for (String txt : texts)
        {
            byte[] enText = encryption.encrypt(txt.getBytes(StandardCharsets.UTF_8), priKey, null);
            byte[] deText = encryption.decrypt(enText, pubKey, null);
            System.out.println("text len:" + txt.length() + ",decryption text:" + new String(deText));
        }
    }
}