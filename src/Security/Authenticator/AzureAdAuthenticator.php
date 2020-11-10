<?php

namespace Alancting\OAuth2\OpenId\Client\Security\Authenticator;

use Alancting\OAuth2\OpenId\Client\Security\Authenticator\AbstractMicrosoftAuthenticator;
use Alancting\OAuth2\OpenId\Client\Security\Credential\MicrosoftOAuthCredential;

class AzureAdAuthenticator extends AbstractMicrosoftAuthenticator
{
    protected function getOAuthCredentialClass()
    {
        return 'Alancting\OAuth2\OpenId\Client\Security\Credential\AzureAdOAuthCredential';
    }
}