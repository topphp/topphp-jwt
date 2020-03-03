<?php
/**
 * 凯拓软件 [临渊羡鱼不如退而结网,凯拓与你一同成长]
 * Project: topphp-client
 * Date: 2020/2/29 10:36
 * Author: bai <sleep@kaituocn.com>
 */

/**
 * Description - topphpJwt.php
 *
 * Topphp JWT 配置
 */

return [
    // 是否使用rsa公私钥方式进行JWT签名 默认HMAC
    "use_rsa"     => false,
    // RSA 公钥地址 为空默认获取根目录下 pem 中的公钥地址
    "rsa_pub_key" => "",
    // RSA 私钥地址 为空默认获取根目录下 pem 中的私钥地址
    "rsa_pri_key" => "",
];
