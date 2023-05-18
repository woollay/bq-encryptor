package com.biuqu.encryption.impl;

import com.biuqu.encryption.BaseSingleEncryption;
import com.biuqu.encryption.BaseSingleEncryptionTest;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import java.nio.charset.StandardCharsets;

public class AesEncryptionTest extends BaseSingleEncryptionTest
{
    @Test
    public void encryptLen()
    {
        int[] keyLenList = {128, 192, 256};
        //test1:AES可以分段(分组)加密明文长度为n的明文数据，在默认有填充的情况下，密文长度为(n/16+1)*16的倍数(除法取整)
        for (int keyLen : keyLenList)
        {
            BaseSingleEncryption encryption = new AesEncryption();
            super.encrypt(encryption, keyLen, 16);
        }
    }

    @Test
    public void testEncryptPadding()
    {
        int[] keyLenList = {128, 192, 256};
        String[] modes = {"ECB", "CBC", "CTR", "CFB"};
        String[] paddings = {"NoPadding", "PKCS5Padding"};
        for (int keyLen : keyLenList)
        {
            BaseSingleEncryption encryption = new AesEncryption();
            super.doCipher(encryption, keyLen, paddings, modes);
        }
    }

    @Test
    public void testEncrypt()
    {
        String text = "test aes 256 ecb ...";
        byte[] key = Hex.decode("d2ad9a80dbc23c330d49694b73e99768f49a720bf596f1bb8f43bf47c2a6f0f0");
        System.out.println("key len=" + key.length);
        byte[] enText = encryption.encrypt(text.getBytes(StandardCharsets.UTF_8), key, null);
        System.out.println("enText=" + Hex.toHexString(enText));
        byte[] deText = encryption.decrypt(enText, key, null);
        System.out.println("deText=" + new String(deText));
    }

    @Test
    public void testNacosKey()
    {
        String text = "BiuQuIsASampleToolsAndDemo-UsefulForYourMicroserviceProjects";
        byte[] key = Hex.decode("d2ad9a80dbc23c330d49694b73e99768f49a720bf596f1bb8f43bf47c2a6f0f0");
        System.out.println("key len=" + key.length);
        byte[] enText = encryption.encrypt(text.getBytes(StandardCharsets.UTF_8), key, null);
        String base64 = Base64.toBase64String(enText);
        System.out.println("enText=" + Hex.toHexString(enText) + ",base64=" + base64 + ",len=" + base64.length());
        byte[] enText2 = Base64.decode(base64);
        System.out.println("enText2=" + new String(enText2).length());

    }

    @Test
    public void createKey()
    {
        int[] keyLenList = {128, 192, 256};
        for (int keyLen : keyLenList)
        {
            BaseSingleEncryption encryption = new AesEncryption();
            encryption.setEncryptLen(keyLen);
            super.createKey(encryption, keyLen);
        }
    }

    @Test
    public void toKey()
    {
        int[] keyLenList = {128, 192, 256};
        for (int keyLen : keyLenList)
        {
            BaseSingleEncryption encryption = new AesEncryption();
            encryption.setEncryptLen(keyLen);
            super.toKey(encryption, 16);
        }
    }

    private AesEncryption encryption = new AesEncryption();
}