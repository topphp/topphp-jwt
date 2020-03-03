<?php
/**
 * 凯拓软件 [临渊羡鱼不如退而结网,凯拓与你一同成长]
 * Project: topphp-client
 * Date: 2020/2/29 10:36
 * Author: bai <sleep@kaituocn.com>
 */
declare(strict_types=1);

namespace Topphp\TopphpJwt;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Rsa\Sha256 as RsaSha256;
use Lcobucci\JWT\ValidationData;

class JWT
{
    // 初始化属性【无需修改】
    private static $instance; // 该类实例
    private $rsaPrivateKey = null;
    private $rsaPublicKey = null;
    private $signer = null;
    private $errorLog = "";
    private $token; // 加密后的token
    private $decodeToken; // 解析JWT得到的token对象
    private $decodeRefreshToken; // 解析JWT得到的refreshToken对象
    private $isRefreshToken = false;
    private $refresh = "";// 刷新Token标识符

    // jwt参数，全部参数建议但不强制使用【初始化参数无需修改】
    private $iss = ''; // 该JWT的签发者url
    private $sub = ''; // 该JWT所面向的用户，用于处理特定应用，类似该jwt的主题
    private $aud = ''; // 接受者的url地址
    private $exp = ''; // 该JWT的销毁时间；unix时间戳
    private $nbf = ''; // 该JWT的使用时间不能早于该时间；unix时间戳
    private $iat = ''; // 该JWT的签发时间；unix 时间戳
    private $jti = ''; // 该JWT的唯一ID编号
    private $rtk = ''; // 该JWT的refreshToken
    private $data = '';// 自定义JWT参数【claim 声明一个新配置参数】

    // jwt密钥【可自行定义修改,如果使用RSA形式签名，可忽略此参数，并务必设置公私钥】
    private $secret = '6C5eEE0BcA1480081371B525Bf198AE2';
    private $allowExpNever = false; // 是否允许设置永不过期JWT 默认不允许
    private $defAddUseSec = 0; // 配置JWT使用时间默认增加量，单位s【签发后多久开始生效】
    private $defAddExpSec = 3600; // 配置JWT过期时间默认增加量，单位s【签发后多久过期】
    private $defRefTokenSec = 14 * 24 * 3600; // 配置JWT refreshToken 默认增加量，单位s【默认14天】

    /**
     * 构造函数【单例模式】
     * JWT constructor.
     * @param string $public_key_file string RSA公钥文件路径【验证token】
     * @param string $private_key_file string RSA私钥文件路径【生成token】
     * @author bai
     */
    private function __construct(string $public_key_file, string $private_key_file)
    {
        if ($public_key_file) {
            $this->getPublicKey($public_key_file);
        }
        if ($private_key_file) {
            $this->getPrivateKey($private_key_file);
        }
        if (empty($public_key_file) || empty($private_key_file)) {
            $this->signer = new Sha256();
        }
    }

    /**
     * 获取公钥文件内容
     *
     * @param $file
     * @author bai
     */
    private function getPublicKey(string $file)
    {
        $key_content = $this->readFile($file, "publicKey file");
        if ($key_content) {
            $this->signer       = new RsaSha256();
            $this->rsaPublicKey = $key_content;
        }
    }

    /**
     * 获取私钥文件内容
     *
     * @param $file
     * @author bai
     */
    private function getPrivateKey(string $file)
    {
        $key_content = $this->readFile($file, "privateKey file");
        if ($key_content) {
            $this->signer        = new RsaSha256();
            $this->rsaPrivateKey = $key_content;
        }
    }

    /**
     * 读取文件内容
     *
     * @param $file
     * @param string $type
     * @return bool|false|string
     * @author bai
     */
    private function readFile(string $file, string $type = "file")
    {
        $ret = false;
        if (file_exists($file)) {
            $ret = file_get_contents($file);
        } elseif (preg_match("/-----BEGIN PUBLIC KEY-----/", $file)
            || preg_match("/-----BEGIN PRIVATE KEY-----/", $file)) {
            $ret = $file;
        } else {
            $this->errorLog = "The {$type} {$file} is not exists";
        }
        return $ret;
    }

    /**
     * 创建refreshToken标识符，用于验证token是否是refreshToken类型
     *
     * @param $str
     * @param string $salt
     * @return string
     * @author bai
     */
    private function refreshTokenSecret(string $str = "refreshToken", string $salt = "EqyPF6")
    {
        return md5(md5($str . $salt));
    }

    /**
     * 生成令牌后的保存操作（例如存到redis中）
     *
     * @param string $token
     * @param string $refreshToken
     * @author bai
     */
    private function saveToken(string $token = "", string $refreshToken = "")
    {
        $this->token = $token;
        $this->rtk   = $refreshToken;
        // 保存Token的操作（可选）
    }

    /**
     * 是否是json数据
     *
     * @param $str
     * @return bool
     * @author bai
     */
    private function isJson($str)
    {
        return is_string($str) && !is_null(json_decode($str));
    }

    /**
     * 解密Token
     *
     * @param string $token
     * @return bool|\Lcobucci\JWT\Token
     * @author bai
     */
    private function decode(string $token = null)
    {
        try {
            if (!empty($this->decodeToken) && !$this->isRefreshToken) {
                return $this->decodeToken;
            }
            if (!empty($this->decodeRefreshToken) && $this->isRefreshToken) {
                return $this->decodeRefreshToken;
            }
            if ($this->isRefreshToken) {
                if (empty($token) && empty($this->rtk)) {
                    return false;
                } elseif (empty($token)) {
                    $token = (string)$this->rtk;
                }
            } else {
                if (empty($token) && empty($this->token)) {
                    return false;
                } elseif (empty($token)) {
                    $token = (string)$this->token;
                }
            }
            $parser = new Parser();
            if (!$this->isRefreshToken) {
                $decode = $this->decodeToken = $parser->parse($token);
            } else {
                $decode = $this->decodeRefreshToken = $parser->parse($token);
            }
            $this->iss     = isset($decode->getClaims()['iss']) ? $decode->getClaim('iss') : "";
            $this->sub     = isset($decode->getClaims()['sub']) ? $decode->getClaim('sub') : "";
            $this->aud     = isset($decode->getClaims()['aud']) ? $decode->getClaim('aud') : "";
            $this->jti     = isset($decode->getClaims()['jti']) ? $decode->getClaim('jti') : "";
            $this->iat     = isset($decode->getClaims()['iat']) ? $decode->getClaim('iat') : "";
            $this->nbf     = isset($decode->getClaims()['nbf']) ? $decode->getClaim('nbf') : "";
            $this->exp     = isset($decode->getClaims()['exp']) ? $decode->getClaim('exp') : "";
            $this->data    = isset($decode->getClaims()['data']) ? $decode->getClaim('data') : "";
            $this->refresh = isset($decode->getClaims()['refresh']) ? $decode->getClaim('refresh') : "";
            return $decode;
        } catch (\Exception $e) {
            $this->errorLog = $e->getMessage();
            return false;
        }
    }

    /**
     * 私有化克隆
     *
     * @author bai
     */
    private function __clone()
    {
    }


    //************************************ --- JWT公共方法 --- ****************************************//


    /**
     * 该类的实例
     *
     * @param string $public_key_file
     * @param string $private_key_file
     * @return JWT
     * @author bai
     */
    public static function getInstance(string $public_key_file = '', string $private_key_file = '')
    {
        if (!(self::$instance instanceof self)) {
            self::$instance = new self($public_key_file, $private_key_file);
        }
        return self::$instance;
    }

    /**
     * 获取错误信息
     *
     * @return string
     * @author bai
     */
    public function getErrorMsg()
    {
        return $this->errorLog;
    }

    /**
     * 设置jwtSecret
     *
     * @param string $secret
     * @return $this
     * @author bai
     */
    public function setJwtSecret(string $secret)
    {
        $this->secret = $secret;
        return $this;
    }

    /**
     * 设置ID【jti (例如：登录用户UID)】
     *
     * @param $id
     * @return $this
     * @author bai
     */
    public function setJti(string $id)
    {
        $this->jti = $id;
        return $this;
    }

    /**
     * 设置主题【sub (例如：登录用户名)】
     *
     * @param $title
     * @return $this
     * @author bai
     */
    public function setSub(string $title)
    {
        $this->sub = $title;
        return $this;
    }

    /**
     * 设置签发者URL iss
     *
     * @param $fromUrl
     * @return $this
     * @author bai
     */
    public function setIss(string $fromUrl)
    {
        $this->iss = $fromUrl;
        return $this;
    }

    /**
     * 设置接收者URL aud
     *
     * @param $toUrl
     * @return $this
     * @author bai
     */
    public function setAud(string $toUrl)
    {
        $this->aud = $toUrl;
        return $this;
    }

    /**
     * 设置类内部的加密 $token 值（用于解密）
     *
     * @param $token
     * @return $this
     * @author bai
     */
    public function setToken(string $token)
    {
        $this->token = $token;
        return $this;
    }

    /**
     * 设置获取的是refreshToken信息
     *
     * @return $this
     * @author bai
     */
    public function setIsRefreshToken()
    {
        $this->isRefreshToken = true;
        return $this;
    }

    /**
     * 设置JWT的创建时间（一般为服务器当前时间戳）【iat 签发时间大于当前服务器时间，验证返回失败】
     *
     * @param $now_time
     * @return $this
     * @author bai
     */
    public function setCreTime($now_time = null)
    {
        if (empty($now_time)) {
            $now_time = time();
        }
        $this->iat = $now_time;
        return $this;
    }

    /**
     * 设置JWT的允许使用时间【nbf 使用时间之前不接收处理该Token，验证返回失败】
     *
     * @param $allow_use_time
     * @return $this
     * @author bai
     */
    public function setUseTime($allow_use_time = null)
    {
        if (empty($allow_use_time)) {
            if (empty($this->iat)) {
                $this->iat = time();
            }
            $allow_use_time = $this->iat + $this->defAddUseSec;
        }
        $this->nbf = $allow_use_time;
        return $this;
    }

    /**
     * 设置永不过期
     *
     * @return $this
     * @author bai
     */
    public function setNeverExp()
    {
        $this->allowExpNever = true;
        return $this;
    }

    /**
     * 设置JWT的过期时间【exp 过期时间小于当前服务器时间，验证返回失败】
     *
     * @param $expire_time
     * @return $this
     * @author bai
     */
    public function setExpTime($expire_time = null)
    {
        if (!$this->allowExpNever) {
            if (empty($expire_time)) {
                if (empty($this->iat)) {
                    $this->iat = time();
                }
                $expire_time = $this->iat + $this->defAddExpSec;
            }
            $this->exp = $expire_time;
        }
        return $this;
    }

    /**
     * 设置JWT的自定义参数【数组类型或已经加密过的字符串类型，一般用于存储数据，例如用户信息】
     *
     * @param array $data
     * @return $this
     * @author bai
     */
    public function setData($data = [])
    {
        if (is_array($data)) {
            $this->data = json_encode($data, JSON_UNESCAPED_UNICODE);
        } else {
            $this->data = (string)$data;
        }
        return $this;
    }

    /**
     * 创建Token
     *
     * @param bool $init 是否是初始化 是--返回refreshToken【一般仅用户登录时为true】 不是--不会返回refreshToken
     * @return bool|\Lcobucci\JWT\Token
     * @author bai
     */
    public function createToken(bool $init = false)
    {
        try {
            // 验证入参必须
            if (empty($this->secret) && empty($this->rsaPrivateKey)) {
                $this->errorLog = "Please set the secret";
                return false;
            } elseif (!empty($this->rsaPrivateKey)) {
                $signer_key = $this->rsaPrivateKey;
            } else {
                $signer_key = $this->secret;
            }
            if (empty($this->iat)) {
                $this->iat = time();
            }
            if (empty($this->nbf)) {
                $this->nbf = $this->iat + $this->defAddUseSec;
            }
            if (empty($this->exp)) {
                $this->exp = $this->iat + $this->defAddExpSec;
            }
            // 构建实例
            $signer       = $this->signer;
            $builder      = new Builder();
            $refreshToken = "";
            // 配置
            if (!empty($this->iss)) {
                // This method will be removed on v4
                $builder->setIssuer($this->iss);
            }
            if (!empty($this->sub)) {
                // This method will be removed on v4
                $builder->setSubject($this->sub);
            }
            if (!empty($this->aud)) {
                // This method will be removed on v4
                $builder->setAudience($this->aud);
            }
            if (!empty($this->jti)) {
                // This method will be removed on v4
                $builder->setId($this->jti, true);
            }
            // This method will be removed on v4
            $builder->setIssuedAt($this->iat);
            // This method will be removed on v4
            $builder->setNotBefore($this->nbf);
            // This method will be removed on v4
            if (!$this->allowExpNever) {
                $builder->setExpiration($this->exp);
            }
            // This method will be removed on v4
            $builder->set("data", $this->data);
            // 创建签名
            $builder->sign($signer, $signer_key);
            // 生成令牌
            $token = $builder->getToken();
            if ($init) {
                $builder->setExpiration($this->iat + $this->defRefTokenSec);
                $builder->set("refresh", $this->refreshTokenSecret());
                $builder->sign($signer, $signer_key);
                $refreshToken = $builder->getToken();
            }
            // 这里可以做一些其它的操作，例如把Token放入到Redis内存里面缓存起来。
            $this->saveToken((string)$token, (string)$refreshToken);
            return (string)$token;
        } catch (\Exception $e) {
            $this->errorLog = $e->getMessage();
            return false;
        }
    }

    /**
     * 获取Token全部解密数据
     *
     * @param string $token
     * @return array|bool
     * @author bai
     */
    public function getDecodeAllData(string $token = null)
    {
        try {
            $decode = $this->decode($token);
            if ($decode === false) {
                return false;
            }
            $return = [
                "iss" => $this->iss,
                "sub" => $this->sub,
                "aud" => $this->aud,
                "jti" => $this->jti,
                "iat" => $this->iat,
                "nbf" => $this->nbf,
                "exp" => $this->exp,
            ];
            if ($this->isJson($this->data)) {
                $this->data = json_decode($this->data, true);
            }
            $return['data'] = $this->data;
            return $return;
        } catch (\Exception $e) {
            $this->errorLog = $e->getMessage();
            return false;
        }
    }

    /**
     * 获取Token指定的解密数据
     *
     * @param string $key
     * @param string $token
     * @return bool|mixed
     * @author bai
     */
    public function getDecodeData(string $key = 'data', string $token = null)
    {
        try {
            $allowKey = [
                "iss",
                "sub",
                "aud",
                "jti",
                "iat",
                "nbf",
                "exp",
                "data",
            ];
            if (!in_array($key, $allowKey)) {
                $this->errorLog = "Key is not allowed";
                return false;
            }
            $decode = $this->decode($token);
            if ($decode === false) {
                return false;
            }
            $return = isset($decode->getClaims()[$key]) ? $decode->getClaim($key) : "";
            if ($key == "data") {
                if ($this->isJson($return)) {
                    $return = json_decode($return, true);
                }
            }
            return $return;
        } catch (\Exception $e) {
            $this->errorLog = $e->getMessage();
            return false;
        }
    }

    /**
     * 获取token集合
     *
     * @return array
     * @author bai
     */
    public function getAllToken()
    {
        return [
            "token"        => (string)$this->token,
            "refreshToken" => (string)$this->rtk
        ];
    }

    /**
     * 验证Token
     *
     * @param string $token
     * @return bool
     * @author bai
     */
    public function validateToken(string $token = null)
    {
        try {
            if ($this->isRefreshToken) {
                if (empty($token) && empty($this->rtk)) {
                    return false;
                } elseif (empty($token)) {
                    $token = (string)$this->rtk;
                }
            } else {
                if (empty($token) && empty($this->token)) {
                    return false;
                } elseif (empty($token)) {
                    $token = (string)$this->token;
                }
            }
            if (empty($this->secret) && empty($this->rsaPublicKey)) {
                $this->errorLog = "Please set the secret";
                return false;
            } elseif (!empty($this->rsaPublicKey)) {
                $signer_key = $this->rsaPublicKey;
            } else {
                $signer_key = $this->secret;
            }
            $signer = $this->signer;
            $parse  = $this->decode($token);
            // 验证token签名有效性
            if (!$parse->verify($signer, $signer_key)) {
                $this->errorLog = "Invalid Signature";
                return false;
            }
            // 验证token数据有效性
            $vdata = new ValidationData();
            $vdata->setIssuer($this->iss);
            $vdata->setAudience($this->aud);
            $vdata->setId($this->jti);
            if (!$parse->validate($vdata)) {
                $this->errorLog = "Invalid Token";
                return false;
            }
            // 验证token时间是否过期
            if ($parse->isExpired()) {
                $this->errorLog = "Token Expired";
                return false;
            }
            return true;
        } catch (\Exception $e) {
            $this->errorLog = $e->getMessage();
            return false;
        }
    }

    /**
     * * 根据refreshToken刷新token
     *
     * @param string $refreshToken
     * @param array|bool $data 为true将会清空原jwt中data的数据
     * @param bool $returnRetoken 是否返回带有新的refreshToken的数据
     * @return array|bool
     * @author bai
     */
    public function refreshToken(string $refreshToken, $data = [], bool $returnRetoken = false)
    {
        // 验证refreshToken有效性
        $this->isRefreshToken = true;
        $verify               = $this->validateToken($refreshToken);
        if ($verify === false) {
            $this->errorLog = "Invalid RefreshToken, Please re register Token";
            return false;
        }
        // 确认此token是refreshToken
        if ($this->refresh !== $this->refreshTokenSecret()) {
            $this->errorLog = "This is not a refreshToken";
            return false;
        }
        // 重置数据
        $this->iat = time();
        $this->nbf = $this->iat + $this->defAddUseSec;
        $this->exp = $this->iat + $this->defAddExpSec;
        if (!empty($data) && $data !== true) {
            $this->data = $data;
        } elseif ($data === true) {
            $this->data = [];
        }
        if ($returnRetoken) {
            $this->createToken(true);
            return $this->getAllToken();
        }
        return $this->createToken();
    }
}
