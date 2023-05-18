package com.biuqu.encryption.impl;

import com.biuqu.encryption.MultiEncryption;
import com.biuqu.encryption.converter.impl.PgpKeyConverter;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

public class PgpEncryptionTest
{

    @Test
    public void createKey() throws IOException
    {
        PGPSecretKey secretKey = encryption.createKey(null);
        System.out.println("secretKey=" + Base64.toBase64String(secretKey.getEncoded()));
    }

    @Test
    public void encrypt() throws IOException
    {
        PGPSecretKey secretKey1 = encryption.createKey(null);
        byte[] pri1 = secretKey1.getEncoded();
        System.out.println("pri1=" + Hex.toHexString(pri1));

        PGPSecretKey secretKey2 = encryption.createKey(null);
        byte[] pub2 = secretKey2.getPublicKey().getEncoded();
        System.out.println("pub2=" + Hex.toHexString(pub2));

        String text = "It's a very very good day...";
        byte[] encBytes = encryption.encrypt(text.getBytes(StandardCharsets.UTF_8), pri1, pub2);
        System.out.println("encBytes=" + new String(encBytes, StandardCharsets.UTF_8));

        byte[] pub1 = secretKey1.getPublicKey().getEncoded();
        System.out.println("pub1=" + Hex.toHexString(pub1));
        byte[] pri2 = secretKey2.getEncoded();
        System.out.println("pri2=" + Hex.toHexString(pri2));
        byte[] decBytes = encryption.decrypt(encBytes, pub1, pri2);
        System.out.println("decBytes=" + new String(decBytes, StandardCharsets.UTF_8));

        Assert.assertTrue(text.equalsIgnoreCase(new String(decBytes, StandardCharsets.UTF_8)));
    }

    @Test
    public void decrypt() throws IOException
    {
        String pwd = "BiuQu";
        String kid = "BiuQu-testUser-001";
        long expire = System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365);
        MultiEncryption<PGPSecretKey> encryption = new PgpEncryption(kid, pwd, expire);

        String pgpPath = getClass().getResource("/").getPath() + "pgp/";
        String priPath1 = pgpPath + "pri-test-1.asc";
        String pubPath2 = pgpPath + "pub-test-2.asc";
        byte[] pri1 = PgpKeyConverter.getSecretKey(priPath1).getEncoded();
        byte[] pub2 = PgpKeyConverter.getPublicKey(pubPath2).getEncoded();

        String text = "It's a very very good day...";
        byte[] encBytes = encryption.encrypt(text.getBytes(StandardCharsets.UTF_8), pri1, pub2);
        System.out.println("encBytes=" + new String(encBytes, StandardCharsets.UTF_8));

        String pubPath1 = pgpPath + "pub-test-1.asc";
        String priPath2 = pgpPath + "pri-test-2.asc";
        byte[] pri2 = PgpKeyConverter.getSecretKey(priPath2).getEncoded();
        byte[] pub1 = PgpKeyConverter.getPublicKey(pubPath1).getEncoded();
        byte[] decBytes = encryption.decrypt(encBytes, pub1, pri2);
        Assert.assertTrue(text.equalsIgnoreCase(new String(decBytes, StandardCharsets.UTF_8)));
    }

    private MultiEncryption<PGPSecretKey> encryption = new PgpEncryption("test-001", "pwd", System.currentTimeMillis());

}