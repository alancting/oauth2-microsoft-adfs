<?php

namespace Alancting\OAuth2\Client\Security\Credential;

use Alancting\OAuth2\Client\Security\Credential\MicrosoftOAuthCredential;
use \InvalidArgumentException;
use \UnexpectedValueException;

class AzureAdOAuthCredential extends MicrosoftOAuthCredential
{
    protected function getIdTokenJWTClass()
    {
        return 'Alancting\Microsoft\JWT\AzureAd\AzureAdIdTokenJWT';
    }
}