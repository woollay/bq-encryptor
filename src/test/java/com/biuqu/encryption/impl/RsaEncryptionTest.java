package com.biuqu.encryption.impl;

import com.biuqu.encryption.BaseSingleSignature;
import com.biuqu.encryption.BaseSingleSignatureTest;
import org.apache.commons.lang3.RandomUtils;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public class RsaEncryptionTest extends BaseSingleSignatureTest
{
    @Override
    protected BaseSingleSignature createAlgorithm()
    {
        return new RsaEncryption();
    }

    @Test
    public void encrypt()
    {
        int[] encLengths = {1024, 2048, 3072, 4096};
        List<String> paddings = new ArrayList<>();
        paddings.add("RSA/NONE/NoPadding");
        paddings.add("RSA/ECB/OAEPPadding");
        paddings.add("RSA/ECB/PKCS1Padding");
        paddings.add("RSA/ECB/NoPadding");
        //公钥加密
        super.encrypt(encLengths, paddings);
        //私钥加密
        super.encrypt(encLengths, paddings, false);
    }

    @Test
    public void testEncryptAndSign()
    {
        String initKey = UUID.randomUUID() + new String(RandomUtils.nextBytes(5000), StandardCharsets.UTF_8);

        int[] encLengths = {1024, 2048, 3072, 4096};
        List<String> paddings = new ArrayList<>();
        paddings.add("RSA/ECB/OAEPPadding");
        paddings.add("RSA/ECB/PKCS1Padding");

        BaseSingleSignature encryption = new RsaEncryption();

        for (String padding : paddings)
        {
            encryption.setPaddingMode(padding);
            for (int encLen : encLengths)
            {
                encryption.setEncryptLen(encLen);
                KeyPair keyPair = encryption.createKey(initKey.getBytes(StandardCharsets.UTF_8));
                super.testEncryptAndSign(encryption, keyPair.getPrivate().getEncoded(),
                    keyPair.getPublic().getEncoded());
            }
        }
    }

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
        BaseSingleSignature encryption = new RsaEncryption();
        int[] encLengths = {1024, 2048, 3072, 4096};
        super.createKey(encryption, encLengths);
    }
}