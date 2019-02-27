<?php

namespace Charcoal\Tests\User\Config;

use InvalidArgumentException;

use Charcoal\User\Config\JWTConfig;

use Charcoal\Tests\AbstractTestCase;

class JWTConfigTest extends AbstractTestCase
{
    private $obj;

    public function setUp()
    {
        $this->obj = new JWTConfig();
    }

    public function testSetData()
    {
        $this->obj->setData([
            'privateKey' => 'private',
            'publicKey' => 'public',
            'id' => 'id',
            'issuer' => 'issuer',
            'audience' => 'audience',
            'expiration' => 42
        ]);
        $this->assertEquals('private', $this->obj->privateKey());
        $this->assertEquals('public', $this->obj->publicKey());
        $this->assertEquals('id', $this->obj->id());
        $this->assertEquals('issuer', $this->obj->issuer());
        $this->assertEquals('audience', $this->obj->audience());
        $this->assertEquals(42, $this->obj->expiration());
    }

    public function testSetPrivateKey()
    {
        $ret = $this->obj->setPrivateKey('private');
        $this->assertSame($ret, $this->obj);
        $this->assertEquals('private', $this->obj->privateKey());

        $this->expectException(InvalidArgumentException::class);
        $this->obj->setPrivateKey(false);
    }

    public function testSetPublicKey()
    {
        $ret = $this->obj->setPublicKey('public');
        $this->assertSame($ret, $this->obj);
        $this->assertEquals('public', $this->obj->publicKey());

        $this->expectException(InvalidArgumentException::class);
        $this->obj->setPublicKey(false);
    }

    public function testSetId()
    {
        $ret = $this->obj->setId('id1');
        $this->assertSame($ret, $this->obj);
        $this->assertEquals('id1', $this->obj->id());

        $this->expectException(InvalidArgumentException::class);
        $this->obj->setId(false);
    }
    
    public function testSetIssuer()
    {
        $ret = $this->obj->setIssuer('foobar');
        $this->assertSame($ret, $this->obj);
        $this->assertEquals('foobar', $this->obj->issuer());

        $this->expectException(InvalidArgumentException::class);
        $this->obj->setIssuer(false);
    }

    public function testSetAudience()
    {
        $ret = $this->obj->setAudience('audience2');
        $this->assertSame($ret, $this->obj);
        $this->assertEquals('audience2', $this->obj->audience());

        $this->expectException(InvalidArgumentException::class);
        $this->obj->setAudience(false);
    }

    public function testSetExpiration()
    {
        $ret = $this->obj->setExpiration('42');
        $this->assertSame($ret, $this->obj);
        $this->assertEquals(42, $this->obj->expiration());
    }
}
