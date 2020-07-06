<?php
/**
 * 凯拓软件 [临渊羡鱼不如退而结网,凯拓与你一同成长]
 * @package topphp-jwt
 * @date 2020/7/6 11:16
 * @author sleep <sleep@kaituocn.com>
 */

namespace Topphp\Test;

use Topphp\TopphpJwt\TopJwt;
use Topphp\TopphpTesting\HttpTestCase;

class TopJwtTest extends HttpTestCase
{
    public function testJWT()
    {
        $token = TopJwt::instance(true)
            ->setIat(time())
            ->setExp(1)
            ->encode('1', [
                'id'       => 1,
                'username' => 'sleep'
            ]);
        var_dump($token);
        $this->assertIsString($token);

        $data = TopJwt::instance(true)->decode($token);
        var_dump($data);
    }
}
