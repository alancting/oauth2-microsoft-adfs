<?php

namespace Alancting\OAuth2\Client\Security\Authenticator;

use Alancting\OAuth2\Client\Security\Authenticator\AbstractMicrosoftAuthenticator;
use Alancting\OAuth2\Client\Security\Credential\MicrosoftOAuthCredential;

class AdfsAuthenticator extends AbstractMicrosoftAuthenticator
{
    protected function getClientName()
    {
        return 'adfs';
    }
    
    protected function getLogoutPath()
    {
        return 'adfs_logout';
    }
    
    protected function getConnectPath()
    {
        return 'adfs_check';
    }
    
    protected function getOAuthCredentialKey()
    {
        return 'adfs_oauth_credential';
    }

    protected function getOAuthCredentialClass()
    {
        return 'Alancting\OAuth2\Client\Security\Credential\AdfsOAuthCredential';
    }
}