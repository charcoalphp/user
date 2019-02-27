<?php

namespace Charcoal\Tests\User\Service;

use Exception;
use InvalidArgumentException;

use Slim\Http\Environment;
use Slim\Http\Request;

use Charcoal\User\Config\JWTConfig;
use Charcoal\User\Service\JWTHandler;

use Charcoal\Tests\AbstractTestCase;

/**
 * Class JWTConfigTest
 * @package Charcoal\Tests\User\Service
 */
class JWTConfigTest extends AbstractTestCase
{

    public function testConstructorNoPrivateKey()
    {
        $config = new JWTConfig([
            'publicKey' => __DIR__.'/../../../data/public.key',
        ]);
        $this->expectException(Exception::class);
        $obj = new JWTHandler($config);
    }

    public function testConstructorNoPublicKey()
    {
        $config = new JWTConfig([
            'privateKey' => __DIR__.'/../../../data/private.key',
        ]);
        $this->expectException(Exception::class);
        $obj = new JWTHandler($config);
    }

    public function testConstructorPrivateKeyFileNotExist()
    {
        $config = new JWTConfig([
            'publicKey' => __DIR__.'/../../../data/public.key',
            'privateKey' => 'notFound'
        ]);
        $this->expectException(Exception::class);
        $obj = new JWTHandler($config);
    }

    public function testConstructorPublicKeyFileNotExist()
    {
        $config = new JWTConfig([
            'privateKey' => __DIR__.'/../../../data/private.key',
            'publicKey' => 'notFound'
        ]);
        $this->expectException(Exception::class);
        $obj = new JWTHandler($config);
    }


    public function testGenerateInvalidPrivateKey()
    {
        $config = new JWTConfig([
            'privateKey' => __DIR__.'/../../../data/private-invalid.key',
            'publicKey' => __DIR__.'/../../../data/public.key',
        ]);
        $obj = new JWTHandler($config);

        $this->expectException(InvalidArgumentException::class);
        $obj->generateTokenForUserId(42);
    }

    public function testGenerateTokenForUserId()
    {
        $config = $this->validConfig();
        $obj = new JWTHandler($config);
        $token = $obj->generateTokenForUserId(42);
        $this->assertEquals(42, $token->getClaim('uid'));
    }

    public function testGetTokenFromRequestWithoutHeaders()
    {
        $request  = Request::createFromEnvironment(Environment::mock());
        $config = $this->validConfig();
        $obj = new JWTHandler($config);
        $this->expectException(Exception::class);
        $obj->getTokenFromRequest($request);
    }

    public function testGetTokenFromRequestUnexpectedToken()
    {
        $config = $this->validConfig();
        ;

        $obj = new JWTHandler($config);

        $request = Request::createFromEnvironment(Environment::mock());
        $request = $request->withHeader('HTTP_AUTHORIZATION', 'Bearer foo');

        $this->expectException(Exception::class);
        $obj->getTokenFromRequest($request);
    }

    public function testGetTokenFromRequestInvalidToken()
    {
        $config1 = $this->validConfig();
        $config2 = $this->validConfigDifferent();

        $obj1 = new JWTHandler($config1);
        $obj2 = new JWTHandler($config2);
        $token1 = $obj1->generateTokenForUserId(42);

        $request = Request::createFromEnvironment(Environment::mock());
        $request = $request->withHeader('HTTP_AUTHORIZATION', 'Bearer '.(string)$token1);

        $this->expectException(Exception::class);
        $obj2->getTokenFromRequest($request);
    }

    public function testGetTokenFromRequestInvalidPublicKey()
    {
        $config = new JWTConfig([
            'privateKey' => __DIR__.'/../../../data/private.key',
            'publicKey' => __DIR__.'/../../../data/public-invalid.key',
        ]);
        $obj = new JWTHandler($config);
        $token = $obj->generateTokenForUserId(42);

        $request = Request::createFromEnvironment(Environment::mock());
        $request = $request->withHeader('HTTP_AUTHORIZATION', 'Bearer '.(string)$token);

        $this->expectException(Exception::class);
        $obj->getTokenFromRequest($request);
    }

    public function testGetTokenFromRequest()
    {
        $config = $this->validConfig();
        $obj = new JWTHandler($config);
        $token = $obj->generateTokenForUserId(42);

        $request = Request::createFromEnvironment(Environment::mock());
        $request = $request->withHeader('HTTP_AUTHORIZATION', 'Bearer '.(string)$token);
        $requestToken = $obj->getTokenFromRequest($request);
        $this->assertEquals($token, $requestToken);
        $this->assertEquals($token->getClaim('uid'), $requestToken->getClaim('uid'));
    }

    public function testIsValidTokenInvalidData()
    {
        $config1 = $this->validConfig();
        $config2 = $this->validConfigDifferent();

        $obj1 = new JWTHandler($config1);
        $obj2 = new JWTHandler($config2);

        $token1 = $obj1->generateTokenForUserId(42);
        $token2 = $obj2->generateTokenForUserId(42);

        $this->assertTrue($obj1->isTokenValid($token1));
        $this->assertTrue($obj2->isTokenValid($token2));
        $this->assertFalse($obj1->isTokenValid($token2));
        $this->assertFalse($obj2->isTokenValid($token1));
    }

    public function testIsValidTokenDifferentKeys()
    {
        $config1 = $this->validConfig();
        $config2 = $this->validConfigKey2();

        $obj1 = new JWTHandler($config1);
        $obj2 = new JWTHandler($config2);

        $token1 = $obj1->generateTokenForUserId(42);
        $token2 = $obj2->generateTokenForUserId(42);

        $this->assertTrue($obj1->isTokenValid($token1));
        $this->assertTrue($obj2->isTokenValid($token2));
        $this->assertFalse($obj1->isTokenValid($token2));
        $this->assertFalse($obj2->isTokenValid($token1));
    }

    public function testGetUserIdFromToken()
    {
        $config = $this->validConfig();
        $obj = new JWTHandler($config);
        $token = $obj->generateTokenForUserId('userId');
        $this->assertEquals('userId', $token->getClaim('uid'));
        $this->assertEquals('userId', $obj->getUserIdFromToken($token));
    }

    private function validConfig()
    {
        return new JWTConfig([
            'privateKey' => __DIR__.'/../../../data/private.key',
            'publicKey' => __DIR__.'/../../../data/public.key',
            'id' => 'test'
        ]);
    }

    private function validConfigDifferent()
    {
        return new JWTConfig([
            'privateKey' => __DIR__.'/../../../data/private.key',
            'publicKey' => __DIR__.'/../../../data/public.key',
            'id' => 'different'
        ]);
    }

    private function validConfigKey2()
    {
        return new JWTConfig([
            'privateKey' => __DIR__.'/../../../data/private2.key',
            'publicKey' => __DIR__.'/../../../data/public2.key',
            'id' => 'test'
        ]);
    }
}
