# bq-encryptor加解密组件说明

- 密码学是一门专业，本人作为IT行业的从业者，断断续续与之打交道，深感之美；
- 在广大无私分享者的指引与帮助下，我也积攒了部分经验，不敢私之，仅供来者参考；

## 1. 为什么要写bq-encryptor加解密组件

- 密码学原理较复杂，但是应用阶段，绝大部分时候是不需要关注原理的。而网上一大堆内容在介绍原理，对于实现仅寥寥几笔，容易让涉足者望而却步，我想做到原理和应用隔离，让有兴趣的人快速上手怎么应用加解密；
- 加解密的使用场景相对简单，但是种类较多，网上资料碎片化比较严重，很难系统掌握；
- 加解密其实共性较多，刚好本人在各种业务场景中基本上都有涉足，经过几年的心得体会，抽时间汇总了下简化使用的方法，有一定的避坑作用；
- 国密加解密算法崛起(基本上按照国际规范自研了1套)，刚好按照抽象思维重构了整套加密算法，基本可以做到国密和国际加密算法的无缝切换；
- 国密密改在政府、银行、金融保险行业有很高的安全诉求，在其他行业，也势在必行，但是大部分IT从业者可能并没有接触到，本加密组件也做了较好地模拟实现；

## 2. 为什么要分享bq-encryptor加解密组件

- 简化加解密的使用场景，期望帮助大家提升工作效率；
- 在Java世界里，当前使用最广泛的加解密组件莫过于BouncyCastle(澳大利亚非盈利组织)
  了，毫无疑问，本加解密组件也是基于BouncyCastle做了二次封装，但是同时也屏蔽了其底层实现，期待着有一天我们也有自己的国产的更优实现；
- 深感人生之渺茫，期待着在人类的璀璨星河里，有着我们轻描淡写的一笔；

## 3. 使用bq-encryptor加解密组件有什么好处

- 如`4.2.1`分层设计的包名规划图所示，除了`加密算法`(`encryption`)外，其它的封装皆为`SpringBoot`准备，可以非常方便的注入其中，使用也及其简单；
	- 在SpringBoot yaml中配置如下：
  ```yaml
    bq:
      encrypt:
        #默认加密算法(true表示国密)
        gm: true
        #模拟的加密机(正常情况下，加密机的秘钥是在加密机服务中，此处是不用配置的)
        hsm:
          - algorithm: SM4Hsm
            pri: e9c9ba0326f00c39...
          - algorithm: SM2Hsm
            pri: 3081930201003013...
            pub: 3059301306072a8e...
          - algorithm: SM3Hsm
          - algorithm: GmIntegrityHsm
          - algorithm: AESHsm
            pri: 7c9726e56ce9bc28b...
          - algorithm: RSAHsm
            pri: 308204bc020100...
            pub: 30820122300d0...
          - algorithm: SHAHsm
          - algorithm: UsIntegrityHsm
        #经过加密机加密的jasypt秘钥
        enc: d83b8495e86...
        #经过jasypt加密的适用于本地加密和对外交互数据加密的加密器秘钥
        security:
          - algorithm: SecureSM4
            pri: ENC([key]f7222de...)
          - algorithm: SM4
            pri: ENC([key]5495204...)
          - algorithm: SM2
            pri: ENC([key]61835c8...)
            pub: ENC([key]0b74f34...)
          - algorithm: SM3
          - algorithm: GM
          - algorithm: SecureAES
            pri: ENC([key]6916ae6...)
          - algorithm: AES
            pri: ENC([key]a6b7ecd...)
          - algorithm: RSA
            pri: ENC([key]23708c8...)
            pub: ENC([key]c1ae5a5...)
          - algorithm: SHA-512
          - algorithm: US
          - algorithm: PGP
            pri: ENC([key]29ff6fa...)
            pub: ENC([key]c315ac7...)
            kid: pgpUser01
            pwd: ENC(e71aebdc7b5e...)
            expire: 33219557748024
            #自定义的加密器可以通过`- name:`来区分
  ```
	- 在`SpringBoot`中注入`加密机`：
  ```java
  @Configuration
  public class EncryptHsmConfigurer
  {
    @Bean("hsmBatchKey")
    @ConfigurationProperties(prefix = "bq.encrypt.hsm")
    public List<EncryptorKey> hsmBatchKey()
    {
        List<EncryptorKey> batchKey = new ArrayList<>(Const.TEN);
        return batchKey;
    }

    /**
     * 注入加密机的配置秘钥信息
     *
     * @return 加密机的配置秘钥信息
     */
    @Bean(EncryptorConst.HSM_KEYS)
    public EncryptorKeys hsmKeys(@Qualifier("hsmBatchKey") List<EncryptorKey> batchKey)
    {
        EncryptorKeys keys = new EncryptorKeys();
        keys.setKeys(batchKey);
        keys.setGm(this.gm);
        return keys;
    }

    /**
     * 注入加密机服务门面
     *
     * @param hsmKeys 加密机的配置秘钥信息
     * @return 加密机服务门面
     */
    @Bean(EncryptorConst.HSM_SERVICE)
    public HsmFacade hsmFacade(@Qualifier(EncryptorConst.HSM_KEYS) EncryptorKeys hsmKeys)
    {
        return new HsmFacade(hsmKeys);
    }

    /**
     * 注入业务安全服务
     *
     * @param hsmFacade 加密机服务
     * @return 业务安全服务
     */
    @Bean
    public BizHsmFacade hsmBizFacade(@Qualifier(EncryptorConst.HSM_SERVICE) HsmFacade hsmFacade)
    {
        return new BizHsmFacade(hsmFacade);
    }

    /**
     * 对配置文件中加密的默认类型(国密/国际加密)
     */
    @Value("${bq.encrypt.gm}")
    private boolean gm;    
  }
  ```
	
	- 在`SpringBoot`中注入`jasypt`：
  ```java
  @Configuration
  public class JasyptEncryptConfigurer
  { 
    /**
     * 配置自动加解密的处理器
     *
     * @return 加解密处理器
     */
    @Bean("jasyptStringEncryptor")
    public StringEncryptor getEncryptor()
    {
        String confKey = this.key;
        //兼容有加密机的场景(加密机会对配置文件的加密key进行加密)
        if (null != this.hsmFacade)
        {
            //解密出真实的配置key
            confKey = this.hsmFacade.decrypt(this.key);
        }

        BaseSecureSingleEncryption encryption;
        if (this.gm)
        {
            encryption = EncryptionFactory.SecureSM4.createAlgorithm();
        }
        else
        {
            encryption = EncryptionFactory.SecureAES.createAlgorithm();
        }
        return new JasyptEncryptor(encryption, confKey);
    }

    /**
     * 注入加密机(有才注入，否则忽略)
     */
    @Autowired(required = false)
    private HsmFacade hsmFacade;

    /**
     * 对配置文件是否为国密
     */
    @Value("${bq.encrypt.gm:true}")
    private boolean gm;

    /**
     * 对配置文件加密的sm4 key
     */
    @Value("${bq.encrypt.enc}")
    private String key;   
  }
  ```
	- 在`SpringBoot`中注入`加密安全器`，配置类同加密机的配置类，略。

  > 上述3个`SpringBoot`配置类简单说明了怎么批量注入加解密的对象，后续使用时，仅需通过注解就可以了。这些逻辑本人已全部实现并验证。此处仅了解整体的设计即可。

- 可以支持多种业务场景：
	- 如上配置代码所示，可完美适配`jasypt组件`：支持模拟的加密机对`jasypt组件`的秘钥加密，再使用`jasypt组件`对加密安全器秘钥加密；
	- 支持加密机自动对数据库数据做数据加密和完整性校验；
	- 接口认证数据加密
	- 接口数据防篡改校验
	- 接口数据加密
  > 综上，上述业务场景的实现，会在本人后续的`SpringCloud微服务基础框架`中开源，敬请期待。

## 4. bq-encryptor加解密组件的使用说明

本节将从国际标准的加密分类、bq-encryptor加解密组件的分层、bq-encryptor加解密组件的使用、bq-encryptor加解密组件的实现依次予以介绍。

### 4.1 加解密分类

|名称|全称|类型|`加密长度`|加密/工作模式/填充模式|签名算法|使用场景|典型案例|
|---|---|---|---|---|---|---|---|
|RSA|3人名缩写|非对称加密|~~1024~~<br>2048|- RSA/ECB/PKCS1Padding<br>[RSA/ECB/OAEPWithSHA-1AndMGF1Padding](https://juejin.cn/post/7030953914509836296) <br>RSA/ECB/OAEPWithSHA-256AndMGF1Padding|SHA512WITHRSA<br>SHA256WITHRSA<br>...|加密效率较低，一般不用作加密<br>用做签名|HTTPS证书<br>JwtToken签名|
|SM2|SM2椭圆曲线公钥密码算法|非对称加密|256|-|SM3WithSM2|安全性优于RSA 2048，可用于替代RSA<br>用做签名|国产HTTPS证书<br>国产加密机|
|AES|Advanced Encryption Standard|对称加密|~~128~~<br>~~192~~<br>256|AES/CBC/NoPadding<br>AES/CBC/PKCS5Padding<br>AES/ECB/PKCS5Padding<br>AES/CTR/NoPadding|-|加密效率高，当下只有256位是安全的<br>通常使用CBC/CTR模式加密|各种数据加密|
|SM4|SM4分组密码算法|对称加密|128<br>|SM4/CBC/PKCS5Padding<br>SM4/CTR/NoPadding|-|安全性优于AES 256，可用于替换AES<br>通常使用CBC/CTR模式加密|各种数据加密|
|3DES|Triple Data Encryption Algorithm|对称加密|192<br>|DESede/CBC/NoPadding<br>DESede/CBC/PKCS5Padding<br>DESede/ECB/PKCS5Padding|-|安全性较差，建议使用AES/SM4来替代|各种数据加密|
|SHA-1|Secure Hash Algorithm 1|摘要算法|160<br>|-|-|- 用于内容防篡改|各种报文/下载文件的完整性校验|
|SHA-256|Secure Hash Algorithm 2|摘要算法|256<br>|-|-|- 用于内容防篡改|各种报文/下载文件的完整性校验|
|SHA-512|Secure Hash Algorithm 2|摘要算法|512<br>|-|-|- 用于内容防篡改|各种报文/下载文件的完整性校验|
|SHA3|Secure Hash Algorithm 3|摘要算法|512<br>|-|-|- 用于内容防篡改|各种报文/下载文件的完整性校验|
|SM3|SM3密码杂凑算法|摘要算法|256<br>|-|-|在SHA-256基础上的改进算法，用于替代SHA算法|各种报文/下载文件的完整性校验|
|~~MD5~~|Secure Hash Algorithm 1|摘要算法|~~128~~<|-|-|用于内容防篡改|安全性较差，建议使用SHA-512/SM3来替替代|
|HmacSHA256|Hash-based Message Authentication Code|基于摘要的带认证码的加密算法|256<br>|-|-|用于内容防篡改<br>用于消息认证|安全性一般，曾用于早期的JwtToken认证|
|HmacSHA512|Hash-based Message Authentication Code|基于摘要的带认证码的加密算法|512<br>|-|-|用于内容防篡改<br>用于消息认证|Hmac-SHA256的升级版|
|HmacSM3|Hash-based Message Authentication Code|基于摘要的带认证码的加密算法|256<br>|-|-|用于内容防篡改|Hmac的国产实现，用于替代HmacSHA256|

> `加密长度`: 在加密算法中通常是指分段秘钥的长度，在摘要算法中通常是指内容块的长度；<br>
> `补充说明`: 由于加密长度、填充模式、签名算法的不同，实际上会有非常多的组合使用方式，此处并没有一一列举，但组件基本上都已支持；

### 4.2 bq-encryptor加解密组件的分层

#### 4.2.1 分层整体设计

         加密算法                      加密器                        加密机
     +-------------+             +-------------+             +-------------+
     | encryption  |             |  encryptor  |             |     hsm     |
     |             |  -------->  |             |  -------->  |             |
     +-------------+             +-------------+     |       +-------------+
                                                     |
                                                     |           加密安全器
                                                     |       +-------------+
                                                     |       |   security  |
                                                     +---->  |             |
                                                             +-------------+

> `加密算法`(`encryption`)：提供了**基本的加解密算法能力**，包括生成秘钥，传入报文和秘钥做加解密，还提供了部分证书解析和转换的能力。包名：`com.biuqu.encryption`；<br>
> `加密器`(`encryptor`)：加密算法的封装类，简化了**加解密算法的使用**，初始化加密器时，就需要初始化秘钥，仅需要传入报文做加解密，包名：`com.biuqu.encryptor`；<br>
> `加密机`(`hsm`)：加密器的子类，封装了只需要在系统内部使用秘钥的、安全等级最高的**加密器的使用**，仅需要传入报文做特定的加解密，包名：`com.biuqu.hsm`；<br>
> `加密安全器`(`security`)：加密器的子类，封装了需要与外部交换秘钥、内部安全等级不高的特殊的**加密器的使用**，仅需要传入报文做加解密，包名：`com.biuqu.security`；<br>

- **在实际的业务场景中，基本上只会使用`加密机`(`hsm`)和`加密安全器`(`security`)2种模式，因为很少需要在运行过程中去生成秘钥。**

#### 4.2.2 分层详细设计

- 按照加解密算法类型划分

<table>
	<tr>
	    <th colspan="6">bq-encryptor按照加解密算法类型划分</th>
	</tr>
	<tr>
	    <td>类型</td>
	    <td>抽象类</td>
	    <td>算法名称</td> 
        <td>算法实现类</td> 
        <td>是否安全</td> 
        <td>补充说明</td> 
	</tr>
	<tr>
	    <td rowspan="5">对称加密算法</td>
	    <td rowspan="3">BaseSingleEncryption</td>
	    <td>AES</td>
        <td>AesEncryption</td>
        <td>&#10004;</td>
        <td>只有256位是安全的</td>
	</tr>
	<tr>
        <td>SM4</td>
        <td>Sm4Encryption</td>
        <td>&#10004;</td>
        <td>AES256的国内替代算法</td>
	</tr>
	<tr>
        <td>3DES</td>
        <td>Des3Encryption</td>
        <td>&#x2716;</td>
        <td>不安全算法，不推荐使用</td>
	</tr>
	<tr>
	    <td rowspan="2">BaseSecureSingleEncryption</td>
        <td>AES</td>
        <td>AesSecureEncryption</td>
        <td>&#10004;</td>
        <td>在AES加解密时增加了盐值</td>
	</tr>
	<tr>
        <td>SM4</td>
        <td>Sm4SecureEncryption</td>
        <td>&#10004;</td>
        <td>在SM4加解密时增加了盐值</td>
	</tr>
	<tr>
	    <td rowspan="2">非对称加密算法</td>
	    <td rowspan="2">BaseSingleSignature</td>
	    <td>RSA</td>
        <td>RsaEncryption</td>
        <td>&#10004;</td>
        <td>只有2048位是安全的</td>
	</tr>
	<tr>
        <td>SM2</td>
        <td>Sm2Encryption</td>
        <td>&#10004;</td>
        <td>RSA2048的国内替代算法</td>
	</tr>
	<tr>
	    <td>复合加密算法</td>
	    <td>BaseMultiEncryption</td>
	    <td>PGP</td>
        <td>PgpEncryption</td>
        <td>&#10004;</td>
        <td>一般单独使用签名场景，加解密时效率也高于单独使用相同的非对称加密算法<br>在国际上有使用该协议做敏感报文的加解密</td>
	</tr>
	<tr>
	    <td rowspan="4">复合签名算法</td>
	    <td rowspan="4">BaseMultiSignature</td>
        <td>US</td>
        <td>UsEncryption</td>
        <td>&#10004;</td>
        <td>自定义算法，综合使用了RSA2048/SHA512/AES256算法</td>
	</tr>
    <tr>	    
        <td>GM</td>
        <td>GmEncryption</td>
        <td>&#10004;</td>
        <td>自定义国密算法，综合使用了SM2/SM3/SM4算法</td>
	</tr>
	<tr>
        <td>UsHsm</td>
        <td>UsHsmEncryption</td>
        <td>&#10004;</td>
        <td>自定义算法，应用于加密机场景，综合使用了RSA2048/SHA512</td>
	</tr>
	<tr>
        <td>GmHsm</td>
        <td>GmHsmEncryption</td>
        <td>&#10004;</td>
        <td>自定义国密算法，应用于加密机场景，综合使用了SM2/SM3</td>
	</tr>
	<tr>
	    <td rowspan="2">摘要算法</td>
	    <td rowspan="2">BaseHash</td>
	    <td>SHA-512</td>
        <td>ShaHash</td>
        <td>&#10004;</td>
        <td>SHA摘要算法的通用实现，可支持：SHA-1/SHA-224/SHA-256/SHA-384/SHA-512/SHA3-224/SHA3-256/SHA3-384/SHA3-512/MD5等</td>
	</tr>
	<tr>
        <td>SM3</td>
        <td>Sm3Hash</td>
        <td>&#10004;</td>
        <td>SHA256的国内替代算法</td>
	</tr>
	<tr>
	    <td rowspan="2">HMAC算法</td>
	    <td rowspan="2">KeyHash</td>
	    <td>HMAC</td>
        <td>ShaHmacKeyHash</td>
        <td>&#10004;</td>
        <td>HMAC的通用实现，可支持：HmacSHA1/HmacSHA224/HmacSHA256/HmacSHA384/HmacSHA512/HmacMD5等</td>
	</tr>
	<tr>
        <td>Sm3Hmac</td>
        <td>Sm3HmacKeyHash</td>
        <td>&#10004;</td>
        <td>HMAC的国内替代算法</td>
	</tr>
</table>

> 1. `盐值`：即对应加解密算法中的偏移量；<br>
> 2. `复合签名算法`：`GM`/`US`加密算法为业务场景中的提炼总结，GmHsm/UsHsm为加密机的实际使用经验总结，总之就是要兼顾加解密效率和安全；<br>
> 3. 上述算法实现均基于BouncyCastle做了统一的封装；<br>
> 4. 国际加密算法基本上都有1个与之对应的国密算法(PGP除外)；

- 加密算法的简化使用设计
	- 使用工厂+枚举类的方式(参见`EncryptionFactory`)，可以非常快捷的创建任一个指定的加密算法对象；
	- GM加密算法是综合了多个加密算法对象，做了封装实现：
		- 使用SM3对源报文生成摘要；
		- 使用自持的SM2私钥对摘要签名；
		- 使用新生成的SM4秘钥对源报文加密并生成密文；
		- 再使用对端的SM2公钥对SM4秘钥加密生成加密秘钥；
		- 拼接加密秘钥、签名和密文；
		- GM解密是上述步骤的逆过程；
	- US加密算法实现原理同上；
	- GmHsm加密算法是加密机的最佳实践总结：
		- 使用加密机的SM3对源报文生成摘要；
		- 使用加密机的私钥对摘要做签名；
		- GmHsm解密就是对源报文生成的摘要做验签；
	- UsHsm加密算法实现原理同上；

### 4.3 bq-encryptor加解密组件的使用

- 使用`EncryptionFactory`构建`4.2.2`表中的任意算法实现类并使用加解密，如：
  ```java 
      Sm2Encryption sm2 = EncryptionFactory.SM2.createAlgorithm();
      SecureRandom random = sm2.createRandom(UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8));
      byte[] sm2InitKey = new byte[16];
      random.nextBytes(sm2InitKey);  
  
      String text = "testTextAbc`123";
      KeyPair keyPair = sm2.createKey(sm2InitKey);
      byte[] pubKey = keyPair.getPublic().getEncoded();
      byte[] priKey = keyPair.getPrivate().getEncoded();
      byte[] encryptBytes = sm2.encrypt(text.getBytes(StandardCharsets.UTF_8), pubKey, null);
      byte[] decryptBytes = sm2.decrypt(encryptBytes, priKey, null);
      System.out.println("Decrypt text=" + new String(decryptBytes, StandardCharsets.UTF_8));
  ```
- 使用`EncryptorFactory`构建`4.2.2`表中任意算法对应的加密器并使用加解密，如：
  ```java   
      EncryptorKey sm2Key = new EncryptorKey();
      sm2Key.setAlgorithm(EncryptorFactory.SM2.getAlgorithm());
      sm2Key.setPri(Hex.toHexString(keyPair.getPrivate().getEncoded()));
      sm2Key.setPub(Hex.toHexString(keyPair.getPublic().getEncoded()));
  
      Sm2Encryptor sm2Encryptor = EncryptorFactory.SM2.createEncryptor(sm2Key);
      byte[] encryptBytes = sm2Encryptor.encrypt(text.getBytes(StandardCharsets.UTF_8), null);
      byte[] decryptBytes = sm2Encryptor.decrypt(encryptBytes, null);
      System.out.println("Decrypt text=" + new String(decryptBytes, StandardCharsets.UTF_8));      
  ```
- 使用`SecurityFacade`构建`4.2.2`表中任意算法对应的业务安全加密器并使用加解密，如：
  ```java   
      List<EncryptorKey> keys = new ArrayList<>(32);
      keys.add(sm2Key);
  
      SecurityFacade securityFacade = new SecurityFacade(keys);
      String encryptText = securityFacade.signEncrypt(text);
      String decryptText = securityFacade.signDecrypt(encryptText);
      System.out.println("Decrypt text=" + decryptText);        
  ```
- 使用`HsmFacade`构建`4.2.2`表中任意算法对应的加密机并使用加解密，如：
  ```java   
      List<EncryptorKey> keys = new ArrayList<>(32);
      keys.add(sm2Key);
  
      HsmFacade hsmFacade = new HsmFacade(keys);
      String signText = hsmFacade.sign(text);
      boolean result = hsmFacade.verify(text,signText);
      System.out.println("verify result=" + result);      
  ```  

### 4.4 bq-encryptor加解密组件的实现

- 使用`EncryptionFactory`汇聚了所有加解密算法实现的使用；
- 使用`EncryptorFactory`构建了所有加密器的使用(内置了加密算法和秘钥)；
- 使用`SecurityFacade`构建了本地秘钥和安全要求不高的加解器的使用(除了内置加密算法和秘钥，还内置了一定的安全业务逻辑)；
- 使用`HsmFacade`构建了安全极高的加解器的使用(除了内置加密算法和秘钥，且秘钥是单独硬件安全保存的，还内置了一定的安全业务逻辑)；
- 使用`ClientSecurity`构建了本地秘钥和安全要求不高的加解器的使用(除了`SecurityFacade`的作用外，还可以根据客户指定不同的秘钥)，使得本地秘钥的使用极为方便;
- 后续会基于各种加密算法分别详细分析与总结；
