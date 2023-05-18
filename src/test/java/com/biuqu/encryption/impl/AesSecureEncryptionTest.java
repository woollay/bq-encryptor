package com.biuqu.encryption.impl;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import java.nio.charset.StandardCharsets;

public class AesSecureEncryptionTest
{

    @Test
    public void encrypt()
    {
        String text = "test aes 256 cbc ...";
        byte[] key = Hex.decode("d2ad9a80dbc23c330d49694b73e99768f49a720bf596f1bb8f43bf47c2a6f0f0");
        System.out.println("key len=" + key.length);
        byte[] enText = encryption.encrypt(text.getBytes(StandardCharsets.UTF_8), key, null);
        System.out.println("enText=" + Hex.toHexString(enText));
        byte[] deText = encryption.decrypt(enText, key, null);
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

    private AesEncryption encryption = new AesEncryption();

    private AesSecureEncryption secEncryption = new AesSecureEncryption();
}