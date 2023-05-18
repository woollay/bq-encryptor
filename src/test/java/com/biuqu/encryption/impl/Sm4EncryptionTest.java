package com.biuqu.encryption.impl;

import com.biuqu.encryption.BaseSingleEncryption;
import com.biuqu.encryption.BaseSingleEncryptionTest;
import org.junit.Test;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;

public class Sm4EncryptionTest extends BaseSingleEncryptionTest
{

    @Test
    public void encrypt() throws NoSuchAlgorithmException
    {
        int[] keyLenList = {128};
        //test1:分段(分组)加密明文长度为n的明文数据，在默认有填充的情况下，密文长度为(n/16+1)*16的倍数(除法取整)
        for (int keyLen : keyLenList)
        {
            BaseSingleEncryption encryption = new Sm4Encryption();
            super.encrypt(encryption, keyLen, 16);
        }
    }

    @Test
    public void testEncryptPadding()
    {
        int[] keyLenList = {128};
        String[] modes = {"ECB", "CBC", "CTR", "CFB"};
        String[] paddings = {"NoPadding", "PKCS5Padding"};
        //test1:sm4可以分段(分组)加密明文长度为n的明文数据，密文长度为(n/16+1)*16的倍数(除法取整)
        for (int len : keyLenList)
        {
            BaseSingleEncryption encryption = new Sm4Encryption();
            super.doCipher(encryption, len, paddings, modes);
        }
    }

    @Test
    public void decrypt() throws NoSuchAlgorithmException
    {
    }

    @Test
    public void doCipher()
    {
        Sm4Encryption encryption = new Sm4Encryption();
        encryption.setPaddingMode("SM4/CTR/NoPadding");

        String initKey = "just test sm4 encrypt.";
        SecretKey key = encryption.createKey(initKey.getBytes(StandardCharsets.UTF_8));
        byte[] keyBytes = key.getEncoded();

        String text = "test sm4 crt ...";
        byte[] encBytes = encryption.encrypt(text.getBytes(StandardCharsets.UTF_8), keyBytes, null);
        byte[] decBytes = encryption.decrypt(encBytes, keyBytes, null);
        System.out.println("sm4 dec text=" + new String(decBytes, StandardCharsets.UTF_8));
    }

    @Test
    public void createKey()
    {
        BaseSingleEncryption encryption = new Sm4Encryption();
        super.createKey(encryption, 128);
    }

    @Test
    public void toKey()
    {
        BaseSingleEncryption encryption = new Sm4Encryption();
        super.toKey(encryption, 16);
    }

    private Sm4Encryption encryption = new Sm4Encryption();
}