<?php
/**
 * 凯拓软件 [临渊羡鱼不如退而结网,凯拓与你一同成长]
 * @package topphp-jwt
 * @date 2020/7/6 10:21
 * @author sleep <sleep@kaituocn.com>
 */
declare(strict_types=1);

namespace Topphp\TopphpJwt;

use Topphp\TopphpJwt\exception\BeforeValidException;
use Topphp\TopphpJwt\exception\ExpiredException;
use Topphp\TopphpJwt\exception\SignatureInvalidException;

class TopJwt
{
    private $iss = '';   //jwt签发者
    private $sub = '';   //jwt所面向的用户
    private $aud = '';   //接收jwt的一方
    private $jti = '';   //jwt的唯一身份标识，主要用来作为一次性token。

    private $iat    = 0;      //jwt的签发时间
    private $nbf    = 0;      //定义在什么时间之前，某个时间点后才能访问.该jwt都是不可用的
    private $exp    = 60;     //jwt的过期时间，过期时间必须要大于签发时间
    private $leeway = 0;      //当前时间减去0，把时间留点余地

    private $key  = 'topphp';
    private $data = [];

    /**
     * @return string
     */
    public function getIss(): string
    {
        return $this->iss;
    }

    /**
     * 设置jwt签发者
     * @param string $iss jwt签发者
     * @return TopJwt
     */
    public function setIss(string $iss)
    {
        $this->iss = $iss;
        return $this;
    }

    /**
     * @return string
     */
    public function getSub(): string
    {
        return $this->sub;
    }

    /**
     * 设置jwt所面向的用户
     * @param string $sub
     * @return TopJwt
     */
    public function setSub(string $sub): self
    {
        $this->sub = $sub;
        return $this;
    }

    /**
     * @return string
     */
    public function getAud(): string
    {
        return $this->aud;
    }

    /**
     * 设置接收jwt的一方
     * @param string $aud
     * @return TopJwt
     */
    public function setAud(string $aud): self
    {
        $this->aud = $aud;
        return $this;
    }

    /**
     * @return string
     */
    public function getJti(): string
    {
        return $this->jti;
    }

    /**
     * 设置jwt的唯一身份标识
     * @param string $jti 设置jwt的唯一身份标识
     * @return TopJwt
     */
    public function setJti(string $jti): self
    {
        $this->jti = $jti;
        return $this;
    }

    /**
     * @return int
     */
    public function getIat(): int
    {
        return $this->iat ?? time();
    }

    /**
     * 设置jwt的签发时间
     * @param int $iat 设置jwt的签发时间
     * @return TopJwt
     */
    public function setIat(int $iat): self
    {
        $this->iat = $iat;
        return $this;
    }

    /**
     * @return int
     */
    public function getNbf(): int
    {
        return $this->nbf;
    }

    /**
     * 定义在什么时间之前，某个时间点后才能访问.该jwt都是不可用的
     * @param int $nbf 定义在什么时间之前，某个时间点后才能访问.该jwt都是不可用的
     * @return TopJwt
     */
    public function setNbf(int $nbf): self
    {
        $this->nbf = $nbf;
        return $this;
    }

    /**
     * @return int
     */
    public function getExp(): int
    {
        return $this->exp;
    }

    /**
     * 设置过期时间
     * @param int $exp 多少秒后过期
     * @return TopJwt
     */
    public function setExp(int $exp = 60): self
    {
        $this->exp = $this->getIat() + $exp;
        return $this;
    }

    /**
     * @return int
     */
    public function getLeeway(): int
    {
        return $this->leeway;
    }

    /**
     * @param int $leeway
     * @return TopJwt
     */
    public function setLeeway(int $leeway): self
    {
        $this->leeway = $leeway;
        return $this;
    }

    /**
     * @return string
     */
    public function getKey(): string
    {
        return $this->key;
    }

    /**
     * @param string $key
     * @return TopJwt
     */
    public function setKey(string $key): self
    {
        $this->key = $key;
        return $this;
    }

    /**
     * @return array
     */
    public function getData(): array
    {
        return $this->data;
    }

    /**
     * @param array $data
     * @return TopJwt
     */
    public function setData(array $data): self
    {
        $this->data = $data;
        return $this;
    }

    /**
     * @param bool $isInstance 默认false(为单例),true:多例
     * @return TopJwt|static|null
     * @author sleep
     */
    public static function instance($isInstance = false)
    {
        if (!$isInstance) {
            $instance = null;
            if ($instance instanceof self) {
                return $instance;
            }
        }
        return new self();
    }

    /**
     * 服务器签发token
     * @param string $id 设置唯一身份识别id
     * @param array $data
     * @param string $algo
     * @return string
     * @author sleep
     */
    public function encode($id, array $data, $algo = 'HS256')
    {
        $this->setJti($id);
        $this->setData($data);
        $payload = [
            "jti"  => $this->getJti(),
            "iss"  => $this->getIss(),
            "sub"  => $this->getSub(),
            "aud"  => $this->getAud(),
            "iat"  => $this->getIat() ?? time(),
            "nbf"  => $this->getNbf(),
            "exp"  => $this->getExp(),
            "data" => $this->getData(),
        ];
        return JWT::encode($payload, $this->getKey(), $algo);
    }

    /**
     * 服务器验证token
     * @param $data
     * @param string[] $algo
     * @return object|string|null
     * @author sleep
     */
    public function decode($data, $algo = ['HS256'])
    {
//        try {
        JWT::$leeway = $this->getLeeway();
        return JWT::decode($data, $this->getKey(), $algo);
//        } catch (SignatureInvalidException $e) {
//            //签名不正确
//            return $e->getMessage();
//        } catch (BeforeValidException $e) {
//            // 签名在某个时间点之后才能用
//            return $e->getMessage();
//        } catch (ExpiredException $e) {
//            // token过期
//            return $e->getMessage();
//        } catch (\Exception $e) {
//            return $e->getMessage();
//        }
    }

    /*===========================================================================*/
    public function refreshToken($token)
    {
    }
}
