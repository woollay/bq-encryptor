package com.biuqu.encryption;

import org.apache.commons.lang3.RandomUtils;
import org.junit.Assert;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.*;

public abstract class BaseSingleSignatureTest
{
    public void createKey(BaseSingleSignature encryption, int[] encLengths)
    {
        String format1 = encryption + "[%s] one pri.len=%s,pub.len=%s,cost:%sms.";
        String format2 = encryption + "[%s] sum pri.len=%s,pub.len=%s,avg cost:%sms.";
        for (int encLen : encLengths)
        {
            encryption.setEncryptLen(encLen);
            long avg = 0;
            long sum = 0;
            Set<Integer> priSet = new HashSet<>();
            Set<Integer> pubSet = new HashSet<>();
            for (int i = 0; i < 20; i++)
            {
                long start = System.currentTimeMillis();
                KeyPair keyPair = encryption.createKey(RandomUtils.nextBytes(10));
                long cost = System.currentTimeMillis() - start;
                sum += cost;
                avg = sum / (i + 1);
                int priLen = keyPair.getPrivate().getEncoded().length;
                priSet.add(priLen);
                int pubLen = keyPair.getPublic().getEncoded().length;
                pubSet.add(pubLen);
                System.out.println(String.format(format1, encLen, priLen, pubLen, cost));
            }
            System.out.println(
                String.format(format2, encLen, Arrays.toString(priSet.toArray()), Arrays.toString(pubSet.toArray()),
                    avg));
        }
    }

    public void encrypt(int[] encLengths)
    {
        List<String> paddings = new ArrayList<>();
        paddings.add("");
        encrypt(encLengths, paddings, true);
    }

    public void encrypt(int[] encLengths, List<String> paddings)
    {
        encrypt(encLengths, paddings, true);
    }

    /**
     * 抽象加密测试
     *
     * @param encLengths 秘钥长度集合
     * @param normal     true表示常规的公钥加密，否则表示私钥加密
     */
    public void encrypt(int[] encLengths, List<String> paddings, boolean normal)
    {
        for (int encLen : encLengths)
        {
            long avg = 0;
            long sum = 0;
            int size = 20;
            int encData1Len = 0;
            int encDataNLen = 0;
            for (String padding : paddings)
            {
                BaseSingleSignature encryption1 = createAlgorithm();
                encryption1.setEncryptLen(encLen);
                encryption1.setPaddingMode(padding);
                String format2 = encryption1 + "[%s]sum dec/enc.len=[1-%s]->[%s-%s],avg cost:%sms.";

                for (int i = 1; i <= size; i++)
                {
                    BaseSingleSignature encryption = createAlgorithm();
                    encryption.setPaddingMode(padding);
                    encryption.setEncryptLen(encLen);
                    String format1 = encryption + "[%s]one dec/enc.len=%s->%s,cost:%sms.";
                    KeyPair keyPair = encryption.createKey(RandomUtils.nextBytes(encLen));
                    byte[] data = RandomUtils.nextBytes(i);
                    long start = System.currentTimeMillis();
                    byte[] key = keyPair.getPublic().getEncoded();
                    if (!normal)
                    {
                        key = keyPair.getPrivate().getEncoded();
                    }
                    byte[] encData = encryption.encrypt(data, key, null);
                    if (encData1Len == 0)
                    {
                        encData1Len = encData.length;
                    }
                    else
                    {
                        encDataNLen = encData.length;
                    }
                    long cost = System.currentTimeMillis() - start;
                    System.out.println(String.format(format1, encLen, data.length, encData.length, cost));

                    sum += cost;
                    avg = sum / (i + 1);

                }
                System.out.println(String.format(format2, encLen, size, encData1Len, encDataNLen, avg));
            }
        }
    }

    /**
     * 抽象加密测试
     *
     * @param encryption 加密算法
     * @param encLengths 秘钥长度集合
     * @param normal     true表示常规的公钥加密，否则表示私钥加密
     */
    public void encrypt(BaseSingleSignature encryption, int[] encLengths, boolean normal)
    {

        for (int encLen : encLengths)
        {
            int encBlockLen = encLen / 8;
            encryption.setEncryptLen(encLen);
            String format1 = encryption + "[%s]one dec/enc.len=%s->%s,cost:%sms.";
            String format2 = encryption + "[%s]sum dec/enc.len=[1-%s]->[%s-%s],avg cost:%sms.";
            KeyPair keyPair = encryption.createKey(RandomUtils.nextBytes(encLen));
            long avg = 0;
            long sum = 0;
            int size = encBlockLen * 2 + 1;
            int encData1Len = 0;
            int encDataNLen = 0;
            for (int i = 0; i <= size; i++)
            {
                byte[] data = RandomUtils.nextBytes(i);
                long start = System.currentTimeMillis();
                byte[] key = keyPair.getPublic().getEncoded();
                if (!normal)
                {
                    key = keyPair.getPrivate().getEncoded();
                }
                byte[] encData = encryption.encrypt(data, key, null);
                if (encData1Len == 0)
                {
                    encData1Len = encData.length;
                }
                else
                {
                    encDataNLen = encData.length;
                }
                long cost = System.currentTimeMillis() - start;
                System.out.println(String.format(format1, encLen, data.length, encData.length, cost));

                sum += cost;
                avg = sum / (i + 1);
            }
            System.out.println(String.format(format2, encLen, size, encData1Len, encDataNLen, avg));
        }
    }

    protected void testEncryptAndSign(BaseSingleSignature encryption, byte[] pri, byte[] pub)
    {
        System.out.println("[" + encryption + "]pri/pub key len=" + pri.length + "/" + pub.length);
        String text = UUID.randomUUID() + new String(RandomUtils.nextBytes(1000), StandardCharsets.UTF_8);
        byte[] data = text.getBytes(StandardCharsets.UTF_8);
        long time1 = System.currentTimeMillis();
        byte[] enText = encryption.encrypt(data, pub, null);
        long time2 = System.currentTimeMillis();
        byte[] deText = encryption.decrypt(enText, pri, null);
        long time3 = System.currentTimeMillis();
        long encCost = time2 - time1;
        long decCost = time3 - time2;
        String format = "data[%s] enc len:%s,cost:%s/%sms.";
        System.out.println(String.format(format, data.length, enText.length, encCost, decCost));

        Assert.assertTrue(text.equals(new String(deText, StandardCharsets.UTF_8)));

        byte[] signBytes = encryption.sign(text.getBytes(StandardCharsets.UTF_8), pri);
        //        System.out.println("signBytes=" + Hex.toHexString(signBytes));
        boolean result = encryption.verify(text.getBytes(StandardCharsets.UTF_8), pub, signBytes);
        Assert.assertTrue(result);
    }

    protected abstract BaseSingleSignature createAlgorithm();
}