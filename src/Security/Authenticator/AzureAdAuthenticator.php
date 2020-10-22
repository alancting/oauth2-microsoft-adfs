<?php

namespace Alancting\OAuth2\Client\Security\Authenticator;

use Alancting\OAuth2\Client\Security\Authenticator\AbstractMicrosoftAuthenticator;
use Alancting\OAuth2\Client\Security\Credential\MicrosoftOAuthCredential;

class AzureAdAuthenticator extends AbstractMicrosoftAuthenticator
{
    protected function getClientName()
    {
        return 'azure_ad';
    }
    
    protected function getLogoutPath()
    {
        return 'azure_ad_logout';
    }
    
    protected function getConnectPath()
    {
        return 'azure_ad_connect';
    }
    
    protected function getOAuthCredentialKey()
    {
        return 'azure_ad_oauth_credential';
    }

    protected function getOAuthCredentialClass()
    {
        return 'Alancting\OAuth2\Client\Security\Credential\AzureAdOAuthCredential';
    }
}