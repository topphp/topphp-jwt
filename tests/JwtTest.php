<?php
/**
 * 凯拓软件 [临渊羡鱼不如退而结网,凯拓与你一同成长]
 * Project: topphp-client
 * Date: 2020/2/29 10:36
 * Author: bai <sleep@kaituocn.com>
 */
declare(strict_types=1);

namespace Topphp\Test;

use Topphp\TopphpJwt\JwtHelper;
use Topphp\TopphpTesting\HttpTestCase;

class JwtTest extends HttpTestCase
{
    /**
     * 测试返回原始JWT句柄
     * @throws \Exception
     * @author bai
     */
    public function testJwtHandler()
    {
        $res = JwtHelper::handler();
        $this->assertTrue(!empty($res));
    }

    /**
     * 测试生成Token
     * @throws \Exception
     * @author bai
     */
    public function testGenerateToken()
    {
        $uid   = 1;
        $token = JwtHelper::generateToken($uid);
        $this->assertTrue(is_string($token));
    }

    /**
     * 测试生成带refreshToken的token数据
     * @throws \Exception
     * @author bai
     */
    public function testGenerateRefreshToken()
    {
        $uid      = 1;
        $data     = [
            "uid"      => 1,
            "username" => "张三"
        ];
        $tokenArr = JwtHelper::generateRefreshToken($uid, $data);
        $this->assertTrue(is_array($tokenArr));
    }

    /**
     * 测试验证Token
     * @throws \Exception
     * @author bai
     */
    public function testVerifyToken()
    {
        $uid   = 1;
        $data  = [
            "uid"      => 1,
            "username" => "张三"
        ];
        $token = JwtHelper::generateToken($uid, $data);
        $res   = JwtHelper::verifyToken((string)$token);
        $this->assertTrue($res !== false);
        $this->assertTrue(array_diff($data, $res['data']) == []);
    }

    /**
     * 测试验证Token返回原始JWT全部数据
     * @throws \Exception
     * @author bai
     */
    public function testVerifyTokenReturnJwt()
    {
        $uid   = 1;
        $data  = [
            "uid"      => 1,
            "username" => "张三"
        ];
        $token = JwtHelper::generateToken($uid, $data);
        $res   = JwtHelper::verifyToken((string)$token, true);
        $this->assertTrue($res !== false);
        $this->assertTrue(array_diff($data, $res['data']) == []);
    }

    /**
     * 测试验证签发者url
     * @throws \Exception
     * @author bai
     */
    public function testVerifyTokenUrl()
    {
        $uid  = 1;
        $data = [
            "uid"      => 1,
            "username" => "张三"
        ];
        // $expTime = -1;// generateToken 方法允许设置永久不过期
        $expTime = time() + 7200;// generateToken 方法允许设置指定的过期时间
        $token   = JwtHelper::generateToken($uid, $data, $expTime, "http://domain1.com");
        $res     = JwtHelper::verifyToken((string)$token, false, "http://domain2.com");
        // 签发JWT时声明签发者自己的url（domain1），对方接收到JWT后按照约定的（domain2）验证，发现不符合匹配要求，返回false
        $this->assertTrue($res === false);
    }

    /**
     * 测试刷新Token
     * @throws \Exception
     * @author bai
     */
    public function testRefreshToken()
    {
        $uid      = 1;
        $data1    = [
            "uid"      => 1,
            "username" => "张三"
        ];
        $tokenArr = JwtHelper::generateRefreshToken($uid, $data1);
        $data2    = [
            "uid"      => 1,
            "username" => "李四"
        ];
        // 支持更新data数据
        $token = JwtHelper::refreshToken($tokenArr['refreshToken'], $data2);
        $res   = JwtHelper::verifyToken((string)$token);
        $data3 = (array)$res['data'];
        $this->assertTrue(array_diff($data1, $data3) != []);
    }

    /**
     * 测试刷新Token（返回带refreshToken）
     * @throws \Exception
     * @author bai
     */
    public function testRefreshAllToken()
    {
        $uid  = 1;
        $data = [
            "uid"      => 1,
            "username" => "张三"
        ];
        // 生成带refreshToken的Token数据
        $tokenArr1 = JwtHelper::generateRefreshToken($uid, $data);
        // 根据refreshToken获取新的带refreshToken的Token数据
        $tokenArr2 = JwtHelper::refreshAllToken($tokenArr1['refreshToken']);
        // 验证新的refreshToken是否存在
        $this->assertTrue(!empty($tokenArr2['refreshToken']));
        // 验证新的Token数据是否一致
        $res = JwtHelper::verifyToken((string)$tokenArr2['token']);
        $this->assertTrue(array_diff($data, $res['data']) == []);
    }
}
