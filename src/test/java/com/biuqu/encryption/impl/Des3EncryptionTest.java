package com.biuqu.encryption.impl;

import com.biuqu.encryption.BaseSingleEncryption;
import com.biuqu.encryption.BaseSingleEncryptionTest;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.RandomUtils;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;

import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class Des3EncryptionTest extends BaseSingleEncryptionTest
{
    @Test
    public void createKey() throws NoSuchAlgorithmException
    {
        BaseSingleEncryption encryption = new Des3Encryption();
        try
        {
            //3DES不允许低于24byte的秘钥,因为无法解析出3个8byte的DES秘钥
            super.createKey(encryption, 192);
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }

    @Test
    public void testGetKey()
    {
        BaseSingleEncryption encryption = new Des3Encryption();

        byte[] keyBytes = RandomUtils.nextBytes(24);

        //test1: 任意24byte的内容均可以作为3DES的秘钥
        SecretKey secretKey = encryption.toKey(RandomUtils.nextBytes(24));
        System.out.println("init key=" + Hex.toHexString(keyBytes));
        System.out.println("3des key=" + Hex.toHexString(secretKey.getEncoded()));
        Assert.assertTrue(secretKey.getEncoded().length == 24);

        //test2:秘钥对象的二进制和原始秘钥的二进制并不相同
        Assert.assertFalse(Hex.toHexString(secretKey.getEncoded()).equals(Hex.toHexString(keyBytes)));

        byte[] keyBytes2 = RandomUtils.nextBytes(25);
        //test3: 任意大于24byte的内容均可以作为3DES的秘钥，而且只会截取前24byte
        SecretKey secretKey2 = encryption.toKey(keyBytes2);
        Assert.assertTrue(secretKey2.getEncoded().length == 24);
        byte[] subBytes2 = ArrayUtils.subarray(keyBytes2, 0, 24);
        Assert.assertTrue(Hex.toHexString(secretKey2.getEncoded()).equals(Hex.toHexString(encryption.toKey(subBytes2).getEncoded())));
    }

    @Test
    public void testEncryptLen() throws NoSuchAlgorithmException
    {
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        byte[] keyBytes = new byte[24];
        random.nextBytes(keyBytes);

        BaseSingleEncryption encryption = new Des3Encryption();
        super.encrypt(encryption, 192, 8);
    }

    @Test
    public void testEncrypt()
    {
        int[] keyLenList = {192};
        String[] modes = {"ECB", "CBC", "CTR", "CFB"};
        String[] paddings = {"NoPadding", "PKCS5Padding"};
        //test1:分段(分组)加密明文长度为n的明文数据，密文长度为(n/encGroupLen+1)*encGroupLen的倍数(除法取整)
        for (int len : keyLenList)
        {
            BaseSingleEncryption encryption = new Des3Encryption();
            super.doCipher(encryption, len, 8, paddings, modes);
        }
    }
}