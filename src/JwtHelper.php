<?php
/**
 * 凯拓软件 [临渊羡鱼不如退而结网,凯拓与你一同成长]
 * Project: topphp-client
 * Date: 2020/2/29 10:36
 * Author: bai <sleep@kaituocn.com>
 */

/**
 * Description - JwtHelper.php
 *
 * JWT 助手类
 */


namespace Topphp\TopphpJwt;


class JwtHelper
{
    /**
     * @var JWT
     */
    private static $handler;

    /**
     * 校验URL（jwt-- iss & aud）
     * @param $fromUrl
     * @param $toUrl
     * @param string $allowUrl
     * @return bool
     * @author bai
     */
    private static function checkUrl($fromUrl, $toUrl, $allowUrl = "")
    {
        $audBool = $issBool = true;
        // 校验签发者URL
        if (!empty($allowUrl)) {
            if ($fromUrl !== $allowUrl) {
                $issBool = false;
            }
        }
        // 校验接收者URL
        if (!empty($toUrl)) {
            if (function_exists("request")) {
                $nowRequestUrl = request()->domain() . request()->url();
            } else {
                $http_type     = ((isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] == 'on') || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] == 'https')) ? 'https://' : 'http://';
                $nowRequestUrl = $http_type . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
            }
            if ($nowRequestUrl !== $toUrl) {
                $audBool = false;
            }
        }
        if ($issBool == false || $audBool == false) {
            return false;
        }
        return true;
    }

    /**
     * 返回项目根目录
     * @return mixed
     * @author bai
     */
    private static function rootDir()
    {
        try {
            if (!isset($_SERVER['DOCUMENT_ROOT']) && function_exists("root_path")) {
                return root_path();
            }
            return dirname($_SERVER['DOCUMENT_ROOT']);
        } catch (\Exception $e) {
            return "";
        }
    }

    /**
     * 返回默认公私钥证书目录
     * @return string
     * @author bai
     */
    private static function pemDir()
    {
        return self::rootDir() . DIRECTORY_SEPARATOR . "pem";
    }

    /**
     * publicKey
     * @return string
     * @author bai
     */
    private static function publicKey()
    {
        return self::pemDir() . DIRECTORY_SEPARATOR . "public_key.pem";
    }

    /**
     * privateKey
     * @return string
     * @author bai
     */
    private static function privateKey()
    {
        return self::pemDir() . DIRECTORY_SEPARATOR . "private_key.pem";
    }

    /**
     * 返回原始JWT对象句柄
     * @param string $publicKeyFile
     * @param string $privateKeyFile
     * @return JWT
     * @throws \Exception
     * @author bai
     */
    public static function handler(string $publicKeyFile = '', string $privateKeyFile = '')
    {
        if (empty($publicKeyFile) && function_exists("config")) {
            if (config("topphpJwt.use_rsa") === true) {
                $rsaPub = config("topphpJwt.rsa_pub_key");
                if (!empty($rsaPub) && file_exists($rsaPub)) {
                    $publicKeyFile = $rsaPub;
                } else {
                    $publicKeyFile = self::publicKey();
                }
            }
        }
        if (empty($privateKeyFile) && function_exists("config")) {
            if (config("topphpJwt.use_rsa") === true) {
                $rsaPri = config("topphpJwt.rsa_pri_key");
                if (!empty($rsaPri) && file_exists($rsaPri)) {
                    $privateKeyFile = $rsaPri;
                } else {
                    $privateKeyFile = self::privateKey();
                }
            }
        }
        self::$handler = JWT::getInstance($publicKeyFile, $privateKeyFile);
        return self::$handler;
    }

    /**
     * 获取内部错误信息
     * @return string
     * @throws \Exception
     * @author bai
     */
    public static function getErrorMsg()
    {
        return self::$handler->getErrorMsg();
    }

    /**
     * 生成Token
     * @param int $id jwt唯一标识（如用户UID）
     * @param array $data 附加数据（如用户信息）
     * @param string $expTime 设置过期时间（时间戳）不传默认 1 小时，传 -1 为永不过期
     * @param string $fromUrl 签发者URL
     * @param string $toUrl 接收者URL
     * @return bool|\Lcobucci\JWT\Token
     * @throws \Exception
     * @author bai
     */
    public static function generateToken(
        int $id,
        array $data = [],
        $expTime = "",
        string $fromUrl = "",
        string $toUrl = ""
    ) {
        if ((int)$expTime == -1) {
            return self::handler()->setIss($fromUrl)->setAud($toUrl)->setJti($id)->setNeverExp()->setData($data)->createToken();
        }
        return self::handler()->setIss($fromUrl)->setAud($toUrl)->setJti($id)->setExpTime((int)$expTime)->setData($data)->createToken();
    }

    /**
     * 生成包含refreshToken的全部Token
     * @param int $id jwt唯一标识（如用户UID）
     * @param array $data $data 附加数据（如用户信息）
     * @param string $fromUrl 签发者URL
     * @param string $toUrl 接收者URL
     * @return array 返回数组 token refreshToken
     * @throws \Exception
     * @author bai
     */
    public static function generateRefreshToken(int $id, array $data = [], string $fromUrl = "", string $toUrl = "")
    {
        self::handler()->setIss($fromUrl)->setAud($toUrl)->setJti($id)->setData($data)->createToken(true);
        return self::handler()->getAllToken();
    }

    /**
     * 验证Token
     * @param string $token
     * @param bool $isAll 是否验证成功返回全部数据
     * @param string $allowUrl 准许的签发者url
     * @return array|bool 返回验证成功后的数据数组
     * @throws \Exception
     * @author bai
     */
    public static function verifyToken(string $token, bool $isAll = false, string $allowUrl = "")
    {
        $res = self::handler()->validateToken($token);
        if ($res === true) {
            if ($isAll) {
                $data = self::handler()->getDecodeAllData();
                // 加入校验签发者url的方法
                if (!self::checkUrl($data['iss'], $data['aud'], $allowUrl)) {
                    return false;
                }
            } else {
                $allData = self::handler()->getDecodeAllData();
                // 加入校验签发者url的方法
                if (!self::checkUrl($allData['iss'], $allData['aud'], $allowUrl)) {
                    return false;
                }
                $data['id']          = $allData['jti'];
                $data['create_time'] = date("Y-m-d H:i:s", $allData['iat']);
                $data['expire_time'] = date("Y-m-d H:i:s", $allData['exp']);
                $data['data']        = $allData['data'];
            }
            return $data;
        }
        return false;
    }

    /**
     * 刷新Token（支持更新data中的数据，$data值如果等于true，将会清空原JWT data中的数据）
     * @param string $refreshToken 获取Token时返回的refreshToken
     * @param array|bool $data 返回新的token与refreshToken
     * @return bool|\Lcobucci\JWT\Token
     * @throws \Exception
     * @author bai
     */
    public static function refreshToken(string $refreshToken, $data = [])
    {
        return self::handler()->refreshToken($refreshToken, $data);
    }

    /**
     * 刷新Token（返回值包含新的refreshToken）（支持更新data中的数据，$data值如果等于true，将会清空原JWT data中的数据）
     * @param string $refreshToken 获取Token时返回的refreshToken
     * @param array|bool $data 返回新的token与refreshToken
     * @return bool|\Lcobucci\JWT\Token
     * @throws \Exception
     * @author bai
     */
    public static function refreshAllToken(string $refreshToken, $data = [])
    {
        return self::handler()->refreshToken($refreshToken, $data, true);
    }
}