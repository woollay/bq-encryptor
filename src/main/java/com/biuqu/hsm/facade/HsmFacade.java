package com.biuqu.hsm.facade;

import com.biuqu.encryption.impl.GmHsmEncryption;
import com.biuqu.encryption.impl.UsHsmEncryption;
import com.biuqu.encryptor.BaseEncryptorFacade;
import com.biuqu.encryptor.factory.EncryptorFactory;
import com.biuqu.encryptor.impl.*;
import com.biuqu.encryptor.model.EncryptorKeys;
import com.biuqu.hsm.EncryptHsm;
import com.biuqu.hsm.impl.EncryptHsmImpl;
import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;

/**
 * 加密机门面
 * <p>
 * 1.此处为模拟加密机，仅为加密器的其中一个用途而已
 * 2.加密机门面简化了加解密使用，若要针对二进制加解密可以EncryptHsm中的接口
 *
 * @author BiuQu
 * @date 2023/5/8 00:09
 */
public class HsmFacade extends BaseEncryptorFacade
{
    public HsmFacade(EncryptorKeys keys)
    {
        super(keys);

        //加密机时从门面中摘录出来了加密机的秘钥配置并单独初始化
        EncryptHsmImpl encryptHsm = new EncryptHsmImpl(keys.isGm());
        this.initHsm(encryptHsm);
        this.encryptHsm = encryptHsm;
    }

    /**
     * 加密机中不可逆加密
     *
     * @param data 原始数据
     * @return 摘要数据
     */
    @Override
    public String hash(String data)
    {
        byte[] encBytes = this.getEncryptHsm().hash(data.getBytes(StandardCharsets.UTF_8));
        return Hex.toHexString(encBytes);
    }

    /**
     * 加密机中可逆加密
     *
     * @param data 原始报文
     * @return 加密后的报文
     */
    @Override
    public String encrypt(String data)
    {
        byte[] encBytes = this.getEncryptHsm().encrypt(data.getBytes(StandardCharsets.UTF_8));
        return Hex.toHexString(encBytes);
    }

    /**
     * 加密机中解密
     * <p>
     * 与上面加密对应
     *
     * @param data 加密后的数据
     * @return 解密后的数据
     */
    @Override
    public String decrypt(String data)
    {
        byte[] decBytes = this.getEncryptHsm().decrypt(Hex.decode(data));
        return new String(decBytes, StandardCharsets.UTF_8);
    }

    /**
     * 加密机中的签名
     *
     * @param data 原始数据
     * @return 签名值
     */
    @Override
    public String sign(String data)
    {
        byte[] encBytes = this.getEncryptHsm().sign(data.getBytes(StandardCharsets.UTF_8));
        return Hex.toHexString(encBytes);
    }

    /**
     * 验证签名
     *
     * @param data      原始数据(带签名值)
     * @param signature 签名值
     * @return true表示签名验证通过
     */
    @Override
    public boolean verify(String data, String signature)
    {
        return this.getEncryptHsm().verify(data.getBytes(StandardCharsets.UTF_8), Hex.decode(signature));
    }

    /**
     * 获取模拟加密机的加密器
     *
     * @return 模拟加密机的加密器
     */
    public EncryptHsm getEncryptHsm()
    {
        return encryptHsm;
    }

    /**
     * 初始化模拟加密机的加密器
     *
     * @param encryptHsm 模拟加密机的加密器
     */
    private void initHsm(EncryptHsmImpl encryptHsm)
    {
        //初始化国际加密机封装之后的加密器
        RsaEncryptor rsaEncryptor = this.getEncryptor(EncryptorFactory.RSAHsm.getAlgorithm());
        encryptHsm.setRsaEncryptor(rsaEncryptor);

        AesSecureEncryptor aesEncryptor = this.getEncryptor(EncryptorFactory.AESHsm.getAlgorithm());
        encryptHsm.setAesEncryptor(aesEncryptor);

        ShaHashEncryptor shaEncryptor = this.getEncryptor(EncryptorFactory.SHAHsm.getAlgorithm());
        encryptHsm.setShaEncryptor(shaEncryptor);

        //把国际完整性加密器中的算法对象都替换成加密机中已有的加密器中的算法对象
        UsHsmEncryptor usEncryptor = this.getEncryptor(EncryptorFactory.UsIntegrityHsm.getAlgorithm());
        UsHsmEncryption usEncryption = (UsHsmEncryption)usEncryptor.getEncryption();
        usEncryption.setSignEncryption(rsaEncryptor.getEncryption());
        usEncryptor.setPri(rsaEncryptor.getPri());
        usEncryptor.setPub(rsaEncryptor.getPub());
        usEncryption.setHash(shaEncryptor.getHash());
        encryptHsm.setUsIntegrityEncryptor(usEncryptor);

        //初始化国密加密机封装之后的加密器
        Sm2Encryptor sm2Encryptor = this.getEncryptor(EncryptorFactory.SM2Hsm.getAlgorithm());
        encryptHsm.setSm2Encryptor(sm2Encryptor);

        Sm4SecureEncryptor sm4Encryptor = this.getEncryptor(EncryptorFactory.SM4Hsm.getAlgorithm());
        encryptHsm.setSm4Encryptor(sm4Encryptor);

        Sm3HashEncryptor sm3Encryptor = this.getEncryptor(EncryptorFactory.SM3Hsm.getAlgorithm());
        encryptHsm.setSm3Encryptor(sm3Encryptor);

        //把国密完整性加密器中的算法对象都替换成加密机中已有的加密器中的算法对象
        GmHsmEncryptor gmEncryptor = this.getEncryptor(EncryptorFactory.GmIntegrityHsm.getAlgorithm());
        GmHsmEncryption gmEncryption = (GmHsmEncryption)gmEncryptor.getEncryption();
        gmEncryptor.setPri(sm2Encryptor.getPri());
        gmEncryptor.setPub(sm2Encryptor.getPub());
        gmEncryption.setSignEncryption(sm2Encryptor.getEncryption());
        gmEncryption.setHash(sm3Encryptor.getHash());
        encryptHsm.setGmIntegrityEncryptor(gmEncryptor);
    }

    /**
     * 加密机的抽象接口
     */
    private final EncryptHsm encryptHsm;
}
