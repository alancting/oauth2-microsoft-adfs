<?php

namespace Alancting\OAuth2\OpenId\Client\Test\Security\Token;

use Alancting\OAuth2\OpenId\Client\Security\Token\MicrosoftRefreshToken;
use Alancting\OAuth2\OpenId\Client\Test\Base\AbstractGeneralTestCase;

class MicrosoftRefreshTokenTest extends AbstractGeneralTestCase
{
    protected $mockToken = 'mock-token';

    public function testValidRefreshToken()
    {
        $expire_in = 3600;
        $refreshToken = new MicrosoftRefreshToken($this->mockToken, $expire_in);

        $this->assertRefreshToken([
            'token' => $this->mockToken,
            'is_expired' => false,
        ], $refreshToken);
    }

    public function testExpiredRefreshToken()
    {
        $expire_in = 0;
        $refreshToken = new MicrosoftRefreshToken($this->mockToken, $expire_in);

        $this->assertRefreshToken([
            'token' => $this->mockToken,
            'is_expired' => true,
        ], $refreshToken);
    }

    public function testNotExpiredWithGivenTimestamp()
    {
        $expire_in = 3600;
        $microsoftRefreshToken = new MicrosoftRefreshToken($this->mockToken, $expire_in);

        $this->assertFalse($microsoftRefreshToken->isExpired(time()));
    }

    public function testExpiredWithGivenTimestamp()
    {
        $expire_in = 3600;
        $microsoftRefreshToken = new MicrosoftRefreshToken($this->mockToken, $expire_in);

        $this->assertTrue($microsoftRefreshToken->isExpired(time()+3600));
    }
}