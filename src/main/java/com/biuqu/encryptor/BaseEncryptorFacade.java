package com.biuqu.encryptor;

import com.biuqu.encryptor.factory.EncryptorFactory;
import com.biuqu.encryptor.model.EncryptorKey;
import com.biuqu.encryptor.model.EncryptorKeys;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 抽象的加密器门面
 * <p>
 * 业务场景说明:
 * 1.场景一:用于与外部加密交互(只能使用本地生成的秘钥来做加密、摘要和签名，以及逆过程),参见com.biuqu.security；
 * 2.场景二:用于内部数据的加密交互(为了安全起见，一般使用加密机来做本地数据的加密、摘要和签名，以及逆过程),参见com.biuqu.hsm；
 * <p>
 * 场景一(本地加密)的使用说明:
 * 1.在加密算法的基础上，只封装实现了2套常用和安全的加密器:国际加密器和国密加密器;
 * 2.加密器门面从使用场景出发，只解决加密器的常规使用，如：区分加密器的加密和解密，举例说明:
 * a.有用户A(客户端)使用加密器和己方(服务端)对接，同时己方(客户端)再使用加密器和B方(服务端)对接，假设都使用GM(国密复合算法)；
 * b.己方作为A的服务端，则需要存储1组公私钥(己方私钥1，A方公钥)用于与A的验签和解密(只会调用这两个方法)；
 * c.己方作为B的客户端，则需要存储另1组公私钥(己方私钥2，B方公钥)用于与B的加密和加签(只会调用这两个方法)；
 * 综上，复合加密算法的多秘钥场景下(对应双向加密和签名)，实际上也只会使用己方私钥和另一方公钥，与加密算法类的使用不同；
 * 同理可推出，非对称秘钥的单加密算法的的场景下也是仅限保留1组公私钥(己方私钥3，对方公钥):
 * 公钥不存在时，表示单向加密和验签(己方为服务端);
 * 私钥不存在时，表示单向加密和验签(己方为客户端);
 * <p>
 * 场景二(加密机加密)的使用说明:
 * 1.秘钥不外发，适合做内部数据的加解密，如隐私的数据库数据、文件，一般是存储加密(摘要签名),使用解密(摘要验签);
 * 2.针对场景一(本地加密)使用的本地秘钥，也属于重要隐私数据，需要使用加密机做存储加密，使用解密，一般会做成秘钥管理器，我这里简化下，只做秘钥加解密;
 *
 * @author BiuQu
 * @date 2023/5/3 09:58
 */
public abstract class BaseEncryptorFacade implements EncryptorFacade
{
    public BaseEncryptorFacade(EncryptorKeys keys)
    {
        //初始化所有配置的加密器(根据自定义的名称来初始化，同一类的加密算法可以有多个)
        for (EncryptorKey key : keys.getKeys())
        {
            String algorithm = key.getAlgorithm();
            Encryptor encryptor = EncryptorFactory.newEncryptor(algorithm, key);
            String algorithmName = key.getName();
            if (null == algorithmName)
            {
                algorithmName = algorithm;
            }
            if (null != encryptor)
            {
                ENCRYPTOR_MAP.put(algorithmName, encryptor);
                ENCRYPTOR_KEY_MAP.put(algorithmName, key);
            }
        }
    }

    /**
     * 获取加密器
     *
     * @param name 加密器的唯一名称
     * @return 对称加密器
     */
    public <T extends Encryptor> T getEncryptor(String name)
    {
        return (T)ENCRYPTOR_MAP.get(name);
    }

    /**
     * 创建加密器
     *
     * @param name 加密器的唯一名称
     * @return 加密器
     */
    public <T extends Encryptor> T createEncryptor(String name)
    {
        Encryptor encryptor = null;
        EncryptorKey key = ENCRYPTOR_KEY_MAP.get(name);
        if (null != key)
        {
            encryptor = EncryptorFactory.newEncryptor(name, key);
        }
        return (T)encryptor;
    }

    /**
     * 加密器的集合
     */
    private static final Map<String, Encryptor> ENCRYPTOR_MAP = new ConcurrentHashMap<>();

    /**
     * 加密器的参数配置集合
     */
    private static final Map<String, EncryptorKey> ENCRYPTOR_KEY_MAP = new ConcurrentHashMap<>();
}
