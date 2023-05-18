package com.biuqu.encryption.converter.impl;

import com.biuqu.encryption.BaseSingleSignature;
import com.biuqu.encryption.converter.BasePemConverter;
import com.biuqu.encryption.converter.PemConverter;
import com.biuqu.encryption.impl.RsaEncryption;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class RsaPemConverterTest
{

    @Test
    public void toPubKey() throws FileNotFoundException
    {
        PemConverter converter = new RsaPemConverter();
        byte[] pubKey = converter.toPubKey(new FileInputStream(PUB_PATH));
        System.out.println(PUB_PATH + "[bytes]:" + Hex.toHexString(pubKey));
    }

    @Test
    public void toPriKey() throws FileNotFoundException
    {
        PemConverter converter = new RsaPemConverter();
        byte[] priKey = converter.toPriKey(new FileInputStream(PRI_PATH), null);
        System.out.println(PRI_PATH + "[bytes]:" + Hex.toHexString(priKey));
    }

    @Test
    public void toPem() throws IOException
    {
        String initKey = "test RSA with initial key.";
        BaseSingleSignature encryption = new RsaEncryption();
        KeyPair keyPair = encryption.createKey(initKey.getBytes(StandardCharsets.UTF_8));

        byte[] priKey = keyPair.getPrivate().getEncoded();
        byte[] pubKey = keyPair.getPublic().getEncoded();
        System.out.println(PRI_PATH + "[bytes]:" + Hex.toHexString(priKey));

        String relativeBasePath = "test/";
        String basePath = this.getClass().getResource("/").getPath() + relativeBasePath;
        String priPath = basePath + PRI_PATH;
        String pubPath = basePath + PUB_PATH;
        System.out.println(PRI_PATH + "[path]:" + priPath);

        BasePemConverter converter = new RsaPemConverter();
        converter.toPem(priKey, priPath);
        converter.toPem(pubKey, pubPath);

        Assert.assertTrue(new File(priPath).exists());
        Assert.assertTrue(new File(pubPath).exists());

        InputStream in = new FileInputStream(priPath);

        String context = IOUtils.toString(in, StandardCharsets.UTF_8);
        System.out.println(priPath + "[content]=" + context);
    }

    @Test
    public void toPemObj() throws FileNotFoundException
    {
        RsaPemConverter converter = new RsaPemConverter();
        Object pemObj = converter.toPemObj(new FileInputStream(PRI_PATH));
        Assert.assertTrue(null != pemObj);
    }

    @Test
    public void toPemPriKey() throws FileNotFoundException
    {
        RsaPemConverter converter = new RsaPemConverter();
        Object pemObj = converter.toPemObj(new FileInputStream(PRI_PATH));
        PrivateKey priKey = converter.toPemPriKey(pemObj, null);
        Assert.assertTrue(null != priKey);
    }

    @Test
    public void toPemPubKey() throws FileNotFoundException
    {
        RsaPemConverter converter = new RsaPemConverter();
        Object pemObj = converter.toPemObj(new FileInputStream(PUB_PATH));
        PublicKey pubKey = converter.toPemPubKey(pemObj);
        Assert.assertTrue(null != pubKey);
    }

    @Test
    public void toPair() throws FileNotFoundException
    {
        RsaPemConverter converter = new RsaPemConverter();
        KeyPair pair = converter.toPair(new FileInputStream(PRI_PATH), null);
        Assert.assertTrue(null != pair);
    }

    private static String basePath = RsaPemConverterTest.class.getResource("/").getPath();
    private static String PRI_PATH = basePath + "pem/rsa_pri.pem";
    private static String PUB_PATH = basePath + "pem/rsa_pub.pem";
}