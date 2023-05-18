package com.biuqu.encryptor.constants;

/**
 * 加密器的常量类
 *
 * @author BiuQu
 * @date 2023/5/8 08:17
 */
public final class EncryptorConst
{
    /**
     * 加密机的配置秘钥参数名
     */
    public static final String HSM_KEYS = "hsmKeys";

    /**
     * 加密安全服务的配置秘钥参数名
     */
    public static final String SECURITY_KEYS = "securityKeys";

    /**
     * 加密机的常量服务名
     */
    public static final String HSM_SERVICE = "hsmFacade";

    /**
     * 加密安全的常量服务名
     */
    public static final String SECURITY_SERVICE = "securityFacade";

    private EncryptorConst()
    {
    }
}
