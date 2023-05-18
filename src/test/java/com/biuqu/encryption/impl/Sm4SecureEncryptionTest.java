package com.biuqu.encryption.impl;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.UUID;

public class Sm4SecureEncryptionTest
{

    @Test
    public void encrypt() throws NoSuchAlgorithmException
    {
        String text = "test aes 256 cbc ...";
        byte[] key = Hex.decode("18d7f054716955b50798ff2780f3f830");
        System.out.println("key len=" + key.length);

        byte[] vector = new byte[32];
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        random.setSeed(UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8));
        random.nextBytes(vector);

        byte[] enText = encryption.encrypt(text.getBytes(StandardCharsets.UTF_8), key, vector);
        System.out.println("enText=" + Hex.toHexString(enText));
        byte[] deText = encryption.decrypt(enText, key, vector);
        System.out.println("deText=" + new String(deText));

        byte[] secEnText = secEncryption.encrypt(text.getBytes(StandardCharsets.UTF_8), key, null);
        System.out.println("secEnText=" + Hex.toHexString(secEnText));
        byte[] secDeText = secEncryption.decrypt(secEnText, key, null);
        System.out.println("secDeText=" + new String(secDeText));
    }

    @Test
    public void decrypt()
    {
    }

    private Sm4Encryption encryption = new Sm4Encryption();

    private Sm4SecureEncryption secEncryption = new Sm4SecureEncryption();
}