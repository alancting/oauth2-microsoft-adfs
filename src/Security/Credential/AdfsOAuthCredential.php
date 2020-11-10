<?php

namespace Alancting\OAuth2\OpenId\Client\Security\Credential;

use Alancting\Microsoft\JWT\Adfs\AdfsConfiguration;

class AdfsOAuthCredential extends MicrosoftOAuthCredential
{
    protected function getIdTokenJWTClass()
    {
        return 'Alancting\Microsoft\JWT\Adfs\AdfsIdTokenJWT';
    }

    protected function isSupportConfigurationClass($configuration)
    {
        return ($configuration instanceof AdfsConfiguration) ? true : false;
    }
}