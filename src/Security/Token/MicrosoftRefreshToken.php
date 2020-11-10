<?php

namespace Alancting\OAuth2\OpenId\Client\Security\Token;

class MicrosoftRefreshToken
{
    private $token;
    private $expire;

    public function __construct(string $token, $expire_in)
    {
        $this->token = $token;
        $this->expire = time() + $expire_in;
    }

    public function getToken()
    {
        return $this->token;
    }

    public function isExpired($timestamp = null)
    {
        if (is_null($timestamp)) {
            $timestamp = time();
        }

        if ($timestamp >= $this->expire) {
            return true;
        }

        return false;
    }
}