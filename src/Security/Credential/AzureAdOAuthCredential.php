<?php

namespace Alancting\OAuth2\OpenId\Client\Security\Credential;

use Alancting\Microsoft\JWT\AzureAd\AzureAdConfiguration;

class AzureAdOAuthCredential extends MicrosoftOAuthCredential
{
    protected function getIdTokenJWTClass()
    {
        return 'Alancting\Microsoft\JWT\AzureAd\AzureAdIdTokenJWT';
    }

    protected function isSupportConfigurationClass($configuration)
    {
        return ($configuration instanceof AzureAdConfiguration) ? true : false;
    }
}