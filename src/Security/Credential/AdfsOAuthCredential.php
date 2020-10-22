<?php

namespace Alancting\OAuth2\Client\Security\Credential;

use Alancting\OAuth2\Client\Security\Credential\MicrosoftOAuthCredential;
use \InvalidArgumentException;
use \UnexpectedValueException;

class AdfsOAuthCredential extends MicrosoftOAuthCredential
{
    protected function getIdTokenJWTClass()
    {
        return 'Alancting\Microsoft\JWT\Adfs\AdfsIdTokenJWT';
    }
}