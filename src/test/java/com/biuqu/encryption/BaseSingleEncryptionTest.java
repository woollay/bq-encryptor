package com.biuqu.encryption;

import org.apache.commons.lang3.RandomUtils;
import org.junit.Assert;

import javax.crypto.SecretKey;

public abstract class BaseSingleEncryptionTest
{
    public void createKey(BaseSingleEncryption encryption, int keyLen)
    {
        //test1:使用任意初始值创建秘钥，秘钥始终是固定长度(和加密算法的长度相同)(3DES除外)
        SecretKey key = encryption.createKey(RandomUtils.nextBytes(32));
        Assert.assertTrue(key.getEncoded().length == keyLen / 8);
        SecretKey key2 = encryption.createKey(RandomUtils.nextBytes(64));
        Assert.assertTrue(key2.getEncoded().length == keyLen / 8);
        SecretKey key3 = encryption.createKey(RandomUtils.nextBytes(1));
        Assert.assertTrue(key3.getEncoded().length == keyLen / 8);
    }

    public void toKey(BaseSingleEncryption encryption, int encryptLen)
    {
        //test1:可以使用任意长度值获取秘钥对象(仅能生成秘钥)，但是仅合法长度可以加密
        SecretKey secretKey = encryption.toKey(RandomUtils.nextBytes(encryptLen));
        Assert.assertNotNull(secretKey);
        byte[] data1 = RandomUtils.nextBytes(encryptLen - 1);
        byte[] encBytes1 = encryption.encrypt(data1, secretKey.getEncoded(), null);
        System.out.println("data1 len=" + data1.length + ",enc len=" + encBytes1.length);
        Assert.assertTrue(encBytes1.length == encryptLen);
        Assert.assertNotNull(encryption.toKey(RandomUtils.nextBytes(1)));
        Assert.assertNotNull(encryption.toKey(RandomUtils.nextBytes(2 * encryptLen)));
        Assert.assertNotNull(encryption.toKey(RandomUtils.nextBytes(3 * encryptLen + 1)));

        try
        {
            //test2:秘钥长度高于合法秘钥长度会报错
            byte[] key2 = RandomUtils.nextBytes(encryptLen + 1);
            SecretKey secretKey2 = encryption.toKey(key2);
            System.out.println("secretKey2 len=" + secretKey2.getEncoded().length);
            byte[] data2 = RandomUtils.nextBytes(encryptLen);
            byte[] encBytes2 = encryption.encrypt(data2, secretKey2.getEncoded(), null);
            System.out.println("data2 len=" + data2.length + ",enc len=" + encBytes2.length);
            Assert.fail();
        }
        catch (Exception e)
        {
            e.printStackTrace();
            Assert.assertTrue(true);
        }

        try
        {
            //test3:秘钥长度低于合法秘钥长度会报错
            byte[] key3 = RandomUtils.nextBytes(encryptLen - 1);
            SecretKey secretKey3 = encryption.toKey(key3);
            System.out.println("secretKey3 len=" + secretKey3.getEncoded().length);
            byte[] data3 = RandomUtils.nextBytes(encryptLen);
            byte[] encBytes3 = encryption.encrypt(data3, secretKey3.getEncoded(), null);
            System.out.println("data3 len=" + data3.length + ",enc len=" + encBytes3.length);
            Assert.fail();
        }
        catch (Exception e)
        {
            e.printStackTrace();
            Assert.assertTrue(true);
        }
    }

    public void encrypt(BaseSingleEncryption encryption, int keyLen, int encGroupLen)
    {
        //test1:分段(分组)加密明文长度为n的明文数据，在默认有填充的情况下，密文长度为(n/16+1)*16的倍数(除法取整)
        encryption.setEncryptLen(keyLen);
        SecretKey secretKey = encryption.toKey(RandomUtils.nextBytes(keyLen / 8));
        Assert.assertEquals(secretKey.getEncoded().length, keyLen / 8);

        byte[] data1 = RandomUtils.nextBytes(1);
        byte[] encBytes1 = encryption.encrypt(data1, secretKey.getEncoded(), null);
        System.out.println("[" + keyLen + "]data1 len=" + data1.length + ",enc len=" + encBytes1.length);
        Assert.assertTrue(encBytes1.length == (data1.length / encGroupLen + 1) * encGroupLen);

        byte[] data2 = RandomUtils.nextBytes(encGroupLen - 1);
        byte[] encBytes2 = encryption.encrypt(data2, secretKey.getEncoded(), null);
        System.out.println("[" + keyLen + "]data2 len=" + data2.length + ",enc len=" + encBytes2.length);
        Assert.assertTrue(encBytes2.length == (data2.length / encGroupLen + 1) * encGroupLen);

        byte[] data3 = RandomUtils.nextBytes(encGroupLen);
        byte[] encBytes3 = encryption.encrypt(data3, secretKey.getEncoded(), null);
        System.out.println("[" + keyLen + "]data3 len=" + data3.length + ",enc len=" + encBytes3.length);
        Assert.assertTrue(encBytes3.length == (data3.length / encGroupLen + 1) * encGroupLen);

        byte[] data4 = RandomUtils.nextBytes(2 * encGroupLen - 1);
        byte[] encBytes4 = encryption.encrypt(data4, secretKey.getEncoded(), null);
        System.out.println("[" + keyLen + "]data4 len=" + data4.length + ",enc len=" + encBytes4.length);
        Assert.assertTrue(encBytes4.length == (data4.length / encGroupLen + 1) * encGroupLen);

        byte[] data5 = RandomUtils.nextBytes(2 * encGroupLen);
        byte[] encBytes5 = encryption.encrypt(data5, secretKey.getEncoded(), null);
        System.out.println("[" + keyLen + "]data5 len=" + data5.length + ",enc len=" + encBytes5.length);
        Assert.assertTrue(encBytes5.length == (data5.length / encGroupLen + 1) * encGroupLen);

        byte[] data6 = RandomUtils.nextBytes(3 * encGroupLen + 2);
        byte[] encBytes6 = encryption.encrypt(data6, secretKey.getEncoded(), null);
        byte[] decBytes6 = encryption.decrypt(encBytes6, secretKey.getEncoded(), null);
        System.out.println("[" + keyLen + "]data6 len=" + data6.length + ",enc len=" + encBytes6.length);
        System.out.println("[" + keyLen + "]data6 len=" + data6.length + ",dec len=" + decBytes6.length);
        Assert.assertTrue(encBytes6.length == (data6.length / encGroupLen + 1) * encGroupLen);
        Assert.assertArrayEquals(data6, decBytes6);
    }

    public void doCipher(BaseSingleEncryption encryption, int keyLen, String[] paddings, String[] modes)
    {
        this.doCipher(encryption, keyLen, 16, paddings, modes);
    }

    public void doCipher(BaseSingleEncryption encryption, int keyLen, int encGroupLen, String[] paddings,
        String[] modes)
    {
        //test1:分段(分组)加密明文长度为n的明文数据，存在填充时，密文长度为(n/encGroupLen+1)*encGroupLen的倍数(除法取整)，无填充时为(n/encGroupLen)*encGroupLen的倍数(除法取整，且n必须为encGroupLen的倍数)
        encryption.setEncryptLen(keyLen);
        SecretKey secretKey = encryption.toKey(RandomUtils.nextBytes(keyLen / 8));
        Assert.assertEquals(secretKey.getEncoded().length, keyLen / 8);
        for (String mode : modes)
        {
            for (String padding : paddings)
            {
                StringBuilder alg = new StringBuilder(encryption.getAlgorithm());
                alg.append("/").append(mode);
                alg.append("/").append(padding);
                encryption.setPaddingMode(alg.toString());

                int paddingLen = 0;
                if (!"NoPadding".equals(padding))
                {
                    paddingLen = encGroupLen;
                }
                System.out.println("[" + keyLen + "]padding-1=" + alg);

                byte[] salt = RandomUtils.nextBytes(16);

                if (paddingLen > 0)
                {
                    byte[] data1 = RandomUtils.nextBytes(1);
                    byte[] encBytes1 = encryption.encrypt(data1, secretKey.getEncoded(), salt);
                    byte[] decBytes1 = encryption.decrypt(encBytes1, secretKey.getEncoded(), salt);
                    System.out.println("[" + keyLen + "]padding-1=" + alg + ",enc len=" + encBytes1.length);
                    System.out.println("[" + keyLen + "]padding-1=" + alg + ",dec len=" + decBytes1.length);
                    Assert.assertTrue(encBytes1.length == (data1.length / encGroupLen) * encGroupLen + paddingLen);
                    Assert.assertArrayEquals(data1, decBytes1);
                }

                byte[] data2 = RandomUtils.nextBytes(encGroupLen);
                byte[] encBytes2 = encryption.encrypt(data2, secretKey.getEncoded(), salt);
                byte[] decBytes2 = encryption.decrypt(encBytes2, secretKey.getEncoded(), salt);
                System.out.println("[" + keyLen + "]padding-2=" + alg + ",enc len=" + encBytes2.length);
                System.out.println("[" + keyLen + "]padding-2=" + alg + ",dec len=" + decBytes2.length);
                Assert.assertTrue(encBytes2.length == (data2.length / encGroupLen) * encGroupLen + paddingLen);
                Assert.assertArrayEquals(data2, decBytes2);

                byte[] data3 = RandomUtils.nextBytes(keyLen * 2);
                byte[] encBytes3 = encryption.encrypt(data3, secretKey.getEncoded(), salt);
                byte[] decBytes3 = encryption.decrypt(encBytes3, secretKey.getEncoded(), salt);
                System.out.println("[" + keyLen + "]padding-3=" + alg + ",enc len=" + encBytes3.length);
                System.out.println("[" + keyLen + "]padding-3=" + alg + ",dec len=" + decBytes3.length);
                Assert.assertTrue(encBytes3.length == (data3.length / encGroupLen) * encGroupLen + paddingLen);
                Assert.assertArrayEquals(data3, decBytes3);
            }
        }
    }
}