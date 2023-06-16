package com.biuqu.hsm.facade;

import com.biuqu.encryption.factory.EncryptionFactory;
import com.biuqu.encryption.impl.AesSecureEncryption;
import com.biuqu.encryption.impl.RsaEncryption;
import com.biuqu.encryption.impl.Sm2Encryption;
import com.biuqu.encryption.impl.Sm4SecureEncryption;
import com.biuqu.encryptor.factory.EncryptorFactory;
import com.biuqu.encryptor.model.EncryptorKey;
import com.biuqu.encryptor.model.EncryptorKeys;
import com.biuqu.hsm.BaseEncryptHsm;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public class HsmFacadeTest
{
    @Test
    public void testJasyptKey()
    {
        String hsmKey = "e9c9ba0326f00c39254ee7675907514a";
        String jasyptKey = "f056513b001bda32d80d1c6da4e59e0e";
        List<EncryptorKey> keys = new ArrayList<>(32);
        EncryptorKey sm4Key = new EncryptorKey();
        sm4Key.setPri(hsmKey);
        sm4Key.setAlgorithm(EncryptorFactory.SM4Hsm.getAlgorithm());
        keys.add(sm4Key);

        EncryptorKeys encKeys = new EncryptorKeys();
        encKeys.setGm(true);
        encKeys.setKeys(keys);
        HsmFacade hsm = new HsmFacade(encKeys);

        //1.对jasypt秘钥加密验证
        String encJasyptKey = hsm.encrypt(jasyptKey);
        System.out.println("jasypt dec key:" + jasyptKey + ",enc key:" + encJasyptKey);

        //2.对jasypt秘钥解密验证
        String encJasyptKey2 =
            "d83b8495e866cece729a3666714369d4da2ebc303cf87115913d755ee842d3b4cdc1ac34e9d57ca9f3a51306984260d4";
        String decData2 = hsm.decrypt(encJasyptKey2);
        System.out.println("jasypt enc key:" + encJasyptKey2 + ",dec key:" + decData2);
    }

    @Test
    public void getEncryptHsm()
    {
        HsmFacade hsm = new HsmFacade(encryptorKeys);
        Assert.assertNotNull(hsm.getEncryptHsm());

        System.out.println("gm:" + encryptorKeys.isGm());
        for (EncryptorKey key : encryptorKeys.getKeys())
        {
            String format = "Algorithm[%s],pri[%s],pub[%s],secret[%s].";
            String pri = (key.getPri() == null ? null : key.getPri());
            String pub = (key.getPub() == null ? null : key.getPub());
            String secret = (key.getSecret() == null ? null : key.getSecret());
            String log = String.format(format, key.getAlgorithm(), pri, pub, secret);
            System.out.println(log);
        }
    }

    @Test
    public void hash()
    {
        String test1 = "test abc";
        String result1 = hsm.hash(test1);
        System.out.println(((BaseEncryptHsm)hsm.getEncryptHsm()).getHashEncryptor() + ",encResult=" + result1);
        Assert.assertTrue(result1 != null && result1.equals(hsm.hash(test1)));

        EncryptorKeys keys = new EncryptorKeys();
        keys.setGm(false);
        keys.setKeys(encryptorKeys.getKeys());
        HsmFacade hsm2 = new HsmFacade(keys);

        String result2 = hsm2.hash(test1);
        System.out.println(((BaseEncryptHsm)hsm2.getEncryptHsm()).getHashEncryptor() + ",encResult=" + result2);
        Assert.assertTrue(result2 != null && result2.equals(hsm2.hash(test1)));
    }

    @Test
    public void encrypt()
    {
        String test1 = "test abc";
        String result1 = hsm.encrypt(test1);
        System.out.println(((BaseEncryptHsm)hsm.getEncryptHsm()).getSingleEncryptor() + ",encResult=" + result1);
        Assert.assertTrue(result1 != null && test1.equals(hsm.decrypt(result1)));

        EncryptorKeys keys = new EncryptorKeys();
        keys.setGm(false);
        keys.setKeys(encryptorKeys.getKeys());
        HsmFacade hsm2 = new HsmFacade(keys);

        String result2 = hsm2.encrypt(test1);
        System.out.println(((BaseEncryptHsm)hsm2.getEncryptHsm()).getSingleEncryptor() + ",encResult=" + result2);
        Assert.assertTrue(result2 != null && test1.equals(hsm2.decrypt(result2)));
    }

    @Test
    public void decrypt()
    {
        //测试分段加密
        String test1 =
            "308204bf020100300d06092a864886f70d0101010500048204a9308204a502010002820101009bd6eb95af81056c78c94d056ce868008a115a6adadf2b3002310fcf262b5a5dae705089086d6b6f4f885159953045db0fe86371a3097c9b469eed7e54a053d56be3129d645322a816724e135333e2249b7656cf868799c0e0ce51df6ab7e7ac2ae38f0a22f4cdb96d3c5c632339a9a8f74d1e9a412ef6d8c6fc883b90ed20d2b1702256efb878684dd316abac92d0f4c54d312edf183d1db027243012d9788fce3f87d53a673dbf52b6b365bc812eecb9807c62fee1dd2a1013cf6b46fd1d757eb52513178a5f3449a245e4b128d77f8cd506163789ec4e4cde2ec4971f7921bd26a40803a235ba77dfc3734451058f1e85af7fe4619f62dd9408f6c2016c5d0203010001028201000adabda67ba6b02ec5bbf9ac24d18c3aeb62f98a034c338920c1f390b15f282869c7c3684408c108ac00b9efd42b1c567d856975c70e185a8560f8f84963306ba75bd5d656204f43e76a574353d283901aaef3ad7938952e40ca461c1a660c522adb964135bd98ddaf3cdacf81ead8851f12854ce7b8e273276afbff3021401da8f0823b45699896feb2aaf95f42cef49bc9c32da2b53c0c4823dca165fc24b88f3f20aecfd72a7688fc55c18d710e2d501d0b48ee797bd2b7c8476af8d80b2b6a9e740b6bca1f801bdbb1a02389df0c64e5e699074cba3b89d0c050bc5057668ee945aaeb0d1e7b404c256a8036b1e0d8746fc226b0b5dc210d8ab8b357605902818100c934b3804e2c21ec535a3cf3199973d68dfef777588cd6047607c34c1339bd3a61b5532e9c1681b1038787e73cf0591cc221b995b0b7c98067c84476159c4b5c1834027f4188ea635d0ca169dde1bfc99cedd68cbd074b5654d05b0e55897ff5f48a86d516248316d472829bd2baec2cd53838bf7096e32715fd61d6d745a5a902818100c64773f446bb1fc1dab8773d27138ab7a0e6ac0baed1932d93011f01fef2d900f039488c9f85baa0e90d651fe7b09955dc10f78c63d4ace5324c8354a130d055ba77654b42df4cd8403322b002831c039d14e0f1319e10a7a82d567424726b5c064f38a786167dbf49001b1aadbcbc04eeecbd166dc5593e6f3531f1208699950281810099dc9737928fe511175c762760781c41022ceb88744a9e8ea2c3a4f0d3f2df6579ba7375bd1ee8e63850b7f8787d4367de7c73b2a884a2ae72ae8ecbce12cafe0df417c4c094b6c86d2b6f73c99d0c505c94f3f083ccc42bac87f859a9c78ff6c19dfd258ddd35f18b5c55cc5b055dfd9abf7785cdcf54bd5aef7c9611e0cca102818100b9cfac32773655046ddc00a2264481f2a3ae87fc4acfcb85220622f0d3e2f0c99855964f720ef85e630852841bb3bb7e62c4e3b784b68170283adbb82b767b465b801844f75e1bbd6c2c7f8d424d6bab574181ab863c028f9b632169a5de340e013bac74118c723b184629204f405752a834e2de69f04f39db2d96a7c93b5a2102818100b0d72fccb5d631dc1619a86f7bf34e6f5d93d57114e602a18ee4f168235e900363a5e4f5e9a23662e10c781864dcb51aed69870cf455fbd042928ac445de347b4071cd6b4207616d6c0d3be6061f6ca9dcf907e5f0c979aad97edc59eb73205878cf22429fd286dea2bxxx2425f5b1109a4dcb568d2e20a649a5f52fc416a7";
        String result1 = hsm.encrypt(test1);
        System.out.println(((BaseEncryptHsm)hsm.getEncryptHsm()).getSingleEncryptor() + ",encResult=" + result1);
        Assert.assertTrue(result1 != null && test1.equals(hsm.decrypt(result1)));

        EncryptorKeys keys = new EncryptorKeys();
        keys.setGm(false);
        keys.setKeys(encryptorKeys.getKeys());
        HsmFacade hsm2 = new HsmFacade(keys);

        String result2 = hsm2.encrypt(test1);
        System.out.println(((BaseEncryptHsm)hsm2.getEncryptHsm()).getSingleEncryptor() + ",encResult=" + result2);
        Assert.assertTrue(result2 != null && test1.equals(hsm2.decrypt(result2)));
    }

    @Test
    public void sign()
    {
        String test1 = "test abc";
        String result1 = hsm.sign(test1);
        System.out.println(((BaseEncryptHsm)hsm.getEncryptHsm()).getIntegrityEncryptor() + ",encResult=" + result1);
        Assert.assertTrue(hsm.verify(test1, result1));

        EncryptorKeys keys = new EncryptorKeys();
        keys.setGm(false);
        keys.setKeys(encryptorKeys.getKeys());
        HsmFacade hsm2 = new HsmFacade(keys);

        String result2 = hsm2.sign(test1);
        System.out.println(((BaseEncryptHsm)hsm2.getEncryptHsm()).getIntegrityEncryptor() + ",encResult=" + result2);
        Assert.assertTrue(hsm2.verify(test1, result2));
    }

    @Test
    public void verify()
    {
        //测试分段加密
        String test1 =
            "308204bf020100300d06092a864886f70d0101010500048204a9308204a502010002820101009bd6eb95af81056c78c94d056ce868008a115a6adadf2b3002310fcf262b5a5dae705089086d6b6f4f885159953045db0fe86371a3097c9b469eed7e54a053d56be3129d645322a816724e135333e2249b7656cf868799c0e0ce51df6ab7e7ac2ae38f0a22f4cdb96d3c5c632339a9a8f74d1e9a412ef6d8c6fc883b90ed20d2b1702256efb878684dd316abac92d0f4c54d312edf183d1db027243012d9788fce3f87d53a673dbf52b6b365bc812eecb9807c62fee1dd2a1013cf6b46fd1d757eb52513178a5f3449a245e4b128d77f8cd506163789ec4e4cde2ec4971f7921bd26a40803a235ba77dfc3734451058f1e85af7fe4619f62dd9408f6c2016c5d0203010001028201000adabda67ba6b02ec5bbf9ac24d18c3aeb62f98a034c338920c1f390b15f282869c7c3684408c108ac00b9efd42b1c567d856975c70e185a8560f8f84963306ba75bd5d656204f43e76a574353d283901aaef3ad7938952e40ca461c1a660c522adb964135bd98ddaf3cdacf81ead8851f12854ce7b8e273276afbff3021401da8f0823b45699896feb2aaf95f42cef49bc9c32da2b53c0c4823dca165fc24b88f3f20aecfd72a7688fc55c18d710e2d501d0b48ee797bd2b7c8476af8d80b2b6a9e740b6bca1f801bdbb1a02389df0c64e5e699074cba3b89d0c050bc5057668ee945aaeb0d1e7b404c256a8036b1e0d8746fc226b0b5dc210d8ab8b357605902818100c934b3804e2c21ec535a3cf3199973d68dfef777588cd6047607c34c1339bd3a61b5532e9c1681b1038787e73cf0591cc221b995b0b7c98067c84476159c4b5c1834027f4188ea635d0ca169dde1bfc99cedd68cbd074b5654d05b0e55897ff5f48a86d516248316d472829bd2baec2cd53838bf7096e32715fd61d6d745a5a902818100c64773f446bb1fc1dab8773d27138ab7a0e6ac0baed1932d93011f01fef2d900f039488c9f85baa0e90d651fe7b09955dc10f78c63d4ace5324c8354a130d055ba77654b42df4cd8403322b002831c039d14e0f1319e10a7a82d567424726b5c064f38a786167dbf49001b1aadbcbc04eeecbd166dc5593e6f3531f1208699950281810099dc9737928fe511175c762760781c41022ceb88744a9e8ea2c3a4f0d3f2df6579ba7375bd1ee8e63850b7f8787d4367de7c73b2a884a2ae72ae8ecbce12cafe0df417c4c094b6c86d2b6f73c99d0c505c94f3f083ccc42bac87f859a9c78ff6c19dfd258ddd35f18b5c55cc5b055dfd9abf7785cdcf54bd5aef7c9611e0cca102818100b9cfac32773655046ddc00a2264481f2a3ae87fc4acfcb85220622f0d3e2f0c99855964f720ef85e630852841bb3bb7e62c4e3b784b68170283adbb82b767b465b801844f75e1bbd6c2c7f8d424d6bab574181ab863c028f9b632169a5de340e013bac74118c723b184629204f405752a834e2de69f04f39db2d96a7c93b5a2102818100b0d72fccb5d631dc1619a86f7bf34e6f5d93d57114e602a18ee4f168235e900363a5e4f5e9a23662e10c781864dcb51aed69870cf455fbd042928ac445de347b4071cd6b4207616d6c0d3be6061f6ca9dcf907e5f0c979aad97edc59eb73205878cf22429fd286dea2bxxx2425f5b1109a4dcb568d2e20a649a5f52fc416a7";
        String result1 = hsm.sign(test1);
        System.out.println(((BaseEncryptHsm)hsm.getEncryptHsm()).getIntegrityEncryptor() + ",encResult=" + result1);
        Assert.assertTrue(hsm.verify(test1, result1));

        EncryptorKeys keys = new EncryptorKeys();
        keys.setGm(false);
        keys.setKeys(encryptorKeys.getKeys());
        HsmFacade hsm2 = new HsmFacade(keys);

        String result2 = hsm2.sign(test1);
        System.out.println(((BaseEncryptHsm)hsm2.getEncryptHsm()).getIntegrityEncryptor() + ",encResult=" + result2);
        Assert.assertTrue(hsm2.verify(test1, result2));
    }

    private static final HsmFacade hsm = new HsmFacade(build());
    private static final EncryptorKeys encryptorKeys = build();

    /**
     * 构造加密机的秘钥
     *
     * @return 加密机的秘钥集合
     */
    private static EncryptorKeys build()
    {
        Sm4SecureEncryption encryption = EncryptionFactory.SM4Hsm.createAlgorithm();
        SecureRandom random = encryption.createRandom(UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8));

        Sm4SecureEncryption sm4Encryption = EncryptionFactory.SM4Hsm.createAlgorithm();
        byte[] sm4InitKey = new byte[16];
        random.nextBytes(sm4InitKey);
        SecretKey sm4SecretKey = sm4Encryption.createKey(sm4InitKey);

        List<EncryptorKey> keys = new ArrayList<>(32);
        EncryptorKey sm4Key = new EncryptorKey();
        sm4Key.setPri(Hex.toHexString(sm4SecretKey.getEncoded()));
        sm4Key.setAlgorithm(EncryptorFactory.SM4Hsm.getAlgorithm());
        keys.add(sm4Key);

        Sm2Encryption sm2Encryption = EncryptionFactory.SM2Hsm.createAlgorithm();
        byte[] sm2InitKey = new byte[16];
        random.nextBytes(sm2InitKey);
        KeyPair sm2KeyPair = sm2Encryption.createKey(sm2InitKey);
        EncryptorKey sm2Key = new EncryptorKey();
        sm2Key.setAlgorithm(EncryptorFactory.SM2Hsm.getAlgorithm());
        sm2Key.setPri(Hex.toHexString(sm2KeyPair.getPrivate().getEncoded()));
        sm2Key.setPub(Hex.toHexString(sm2KeyPair.getPublic().getEncoded()));
        keys.add(sm2Key);

        EncryptorKey sm3Key = new EncryptorKey();
        sm3Key.setAlgorithm(EncryptorFactory.SM3Hsm.getAlgorithm());
        keys.add(sm3Key);

        EncryptorKey gmKey = new EncryptorKey();
        gmKey.setAlgorithm(EncryptorFactory.GmIntegrityHsm.getAlgorithm());
        keys.add(gmKey);

        AesSecureEncryption aesEncryption = EncryptionFactory.AESHsm.createAlgorithm();
        byte[] aesInitKey = new byte[16];
        random.nextBytes(aesInitKey);
        SecretKey secretKey = aesEncryption.createKey(aesInitKey);

        EncryptorKey aesKey = new EncryptorKey();
        aesKey.setPri(Hex.toHexString(secretKey.getEncoded()));
        aesKey.setAlgorithm(EncryptorFactory.AESHsm.getAlgorithm());
        keys.add(aesKey);

        RsaEncryption rsaEncryption = EncryptionFactory.RSAHsm.createAlgorithm();
        byte[] rsaInitKey = new byte[16];
        random.nextBytes(rsaInitKey);
        KeyPair rsaKeyPair = rsaEncryption.createKey(rsaInitKey);
        EncryptorKey rsaKey = new EncryptorKey();
        rsaKey.setAlgorithm(EncryptorFactory.RSAHsm.getAlgorithm());
        rsaKey.setPri(Hex.toHexString(rsaKeyPair.getPrivate().getEncoded()));
        rsaKey.setPub(Hex.toHexString(rsaKeyPair.getPublic().getEncoded()));
        keys.add(rsaKey);

        EncryptorKey shaKey = new EncryptorKey();
        shaKey.setAlgorithm(EncryptorFactory.SHAHsm.getAlgorithm());
        keys.add(shaKey);

        EncryptorKey usKey = new EncryptorKey();
        usKey.setAlgorithm(EncryptorFactory.UsIntegrityHsm.getAlgorithm());
        keys.add(usKey);

        EncryptorKeys encryptorKeys = new EncryptorKeys();
        encryptorKeys.setGm(true);
        encryptorKeys.setKeys(keys);
        return encryptorKeys;
    }
}