<?php

namespace Alancting\OAuth2\OpenId\Client\Security\Authenticator;

use Alancting\OAuth2\OpenId\Client\Security\Authenticator\AbstractMicrosoftAuthenticator;
use Alancting\OAuth2\OpenId\Client\Security\Credential\MicrosoftOAuthCredential;

class AdfsAuthenticator extends AbstractMicrosoftAuthenticator
{
    protected function getOAuthCredentialClass()
    {
        return 'Alancting\OAuth2\OpenId\Client\Security\Credential\AdfsOAuthCredential';
    }
}