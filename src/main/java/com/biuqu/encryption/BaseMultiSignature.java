package com.biuqu.encryption;

import com.biuqu.encryption.constants.EncryptionConst;
import com.biuqu.encryption.exception.EncryptionException;
import lombok.Data;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.UUID;

/**
 * 多秘钥签名算法(也包含加密)
 *
 * @author BiuQu
 * @date 2023/4/30 22:04
 */
@Data
public abstract class BaseMultiSignature extends BaseEncryption implements MultiSignature<KeyPair>
{
    /**
     * 构造方法，设置了加密算法的主要参数，还可以通过setter方法设置或者更新
     *
     * @param algorithm   加密算法
     * @param paddingMode 填充模式
     * @param encryptLen  加密长度
     */
    public BaseMultiSignature(String algorithm, String paddingMode, int encryptLen)
    {
        this.setAlgorithm(algorithm);
        this.setPaddingMode(paddingMode);
        this.setEncryptLen(encryptLen);
        this.setRandomMode(RANDOM_MODE);
    }

    @Override
    public KeyPair createKey(byte[] initKey)
    {
        return this.signEncryption.createKey(initKey);
    }

    @Override
    public byte[] encrypt(byte[] data, byte[] pri, byte[] pub)
    {
        try
        {
            byte[] hashBytes = hash.digest(data);
            byte[] signatureBytes = signEncryption.sign(hashBytes, pri);

            byte[] keyBytes = this.getKey();
            if (null == keyBytes)
            {
                SecretKey key = encEncryption.createKey(UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8));
                keyBytes = key.getEncoded();
            }
            byte[] encKeyBytes = this.signEncryption.encrypt(keyBytes, pub, null);
            byte[] encBytes = this.encEncryption.encrypt(data, keyBytes, null);

            StringBuilder builder = new StringBuilder();
            builder.append(Hex.toHexString(signatureBytes)).append(EncryptionConst.POINT);
            builder.append(Hex.toHexString(encKeyBytes)).append(EncryptionConst.POINT);
            builder.append(Hex.toHexString(encBytes));

            return builder.toString().getBytes(StandardCharsets.UTF_8);
        }
        catch (Exception e)
        {
            throw new EncryptionException("failed to sign hash data.", e);
        }
    }

    @Override
    public byte[] decrypt(byte[] data, byte[] pub, byte[] pri)
    {
        try
        {
            String signText = new String(data, StandardCharsets.UTF_8);
            String[] hexData = StringUtils.split(signText, EncryptionConst.POINT);
            int i = 0;

            byte[] signatureBytes = Hex.decode(hexData[i++]);
            byte[] encKeyBytes = Hex.decode(hexData[i++]);
            byte[] encBytes = Hex.decode(hexData[i]);

            byte[] decKeyBytes = this.signEncryption.decrypt(encKeyBytes, pri, null);
            byte[] decBytes = this.encEncryption.decrypt(encBytes, decKeyBytes, null);
            byte[] hashBytes = this.hash.digest(decBytes);
            boolean verifyResult = this.signEncryption.verify(hashBytes, pub, signatureBytes);
            if (verifyResult)
            {
                return decBytes;
            }
        }
        catch (Exception e)
        {
            throw new EncryptionException("failed to verify hash data.", e);
        }
        throw new EncryptionException("failed to verify hash data.");
    }

    @Override
    public byte[] sign(byte[] data, byte[] pri, byte[] pub)
    {
        try
        {
            byte[] hashBytes = hash.digest(data);
            byte[] signBytes = signEncryption.sign(hashBytes, pri);
            byte[] encBytes = signEncryption.encrypt(data, pub, null);

            StringBuilder builder = new StringBuilder();
            builder.append(Hex.toHexString(signBytes)).append(EncryptionConst.POINT);
            builder.append(Hex.toHexString(encBytes));

            return builder.toString().getBytes(StandardCharsets.UTF_8);
        }
        catch (Exception e)
        {
            throw new EncryptionException("failed to sign hash data.", e);
        }
    }

    @Override
    public boolean verify(byte[] data, byte[] pub, byte[] pri)
    {
        try
        {
            String signText = new String(data, StandardCharsets.UTF_8);
            String[] hexData = StringUtils.split(signText, EncryptionConst.POINT);
            int i = 0;
            byte[] signBytes = Hex.decode(hexData[i++]);
            byte[] encBytes = Hex.decode(hexData[i]);

            byte[] decBytes = signEncryption.decrypt(encBytes, pri, null);
            byte[] hashBytes = hash.digest(decBytes);
            return signEncryption.verify(hashBytes, pub, signBytes);
        }
        catch (Exception e)
        {
            throw new EncryptionException("failed to verify signature with hash data.", e);
        }
    }

    /**
     * 获取对称加密算法的秘钥
     *
     * @return 对称加密算法秘钥
     */
    protected byte[] getKey()
    {
        return null;
    }

    /**
     * 定义hash算法
     */
    private Hash hash;

    /**
     * 非对称加密算法(包括签名)
     */
    private BaseSingleSignature signEncryption;

    /**
     * 增强的对称加密算法
     */
    private BaseSecureSingleEncryption encEncryption;
}
