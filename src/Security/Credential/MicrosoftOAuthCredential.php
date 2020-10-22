<?php

namespace Alancting\OAuth2\Client\Security\Credential;

use \InvalidArgumentException;
use \UnexpectedValueException;

use Alancting\Adfs\JWT\Adfs\AdfsAccessTokenJWT;
use Alancting\Adfs\JWT\Adfs\AdfsIdTokenJWT;
use Alancting\OAuth2\Client\Security\Token\MicrosoftRefreshToken;

use Alancting\AzureAd\JWT\AzureAd\AzureAdAccessTokenJWT;
use Alancting\AzureAd\JWT\AzureAd\AzureAdIdTokenJWT;

use GuzzleHttp\Psr7\Uri;

abstract class MicrosoftOAuthCredential
{
    abstract protected function getIdTokenJWTClass();
    
    private $_microsoftConfiguration;
    
    private $_idTokenJWT;
    private $_accessToken;
    private $_expires;
    private $_refreshToken;
    
    private $_otherResourceOAuthCredentials;
    
    public function __construct(
        $microsoftConfiguration,
        $accessToken,
        $otherResourceScopes = []
    ) {
        $this->_microsoftConfiguration = $microsoftConfiguration;
        
        $this->_setAttrByAccessToken($accessToken);
        
        $this->_otherResourceOAuthCredentials = [];
        foreach ($otherResourceScopes as $scope) {
            ($this->_otherResourceOAuthCredentials)[$scope] = false;
        }
    }
    
    public function update($microsoftConfiguration, $accessToken)
    {
        $this->_microsoftConfiguration = $microsoftConfiguration;
        $this->_setAttrByAccessToken($accessToken);
    }

    public function setOtherResourceOAuthCredential($scope, $oAuthCredential)
    {
        ($this->_otherResourceOAuthCredentials)[$scope] = $oAuthCredential;
    }
    
    public function getIdTokenJWT()
    {
        return $this->_idTokenJWT;
    }

    public function getAccessToken()
    {
        return $this->_accessToken;
    }

    public function getRefreshToken()
    {
        return $this->_refreshToken;
    }

    public function getOtherResourceCredentials()
    {
        return $this->_otherResourceOAuthCredentials;
    }

    public function getOtherResourceCredential($scope)
    {
        return isset(($this->_otherResourceOAuthCredentials)[$scope]) ? ($this->_otherResourceOAuthCredentials)[$scope] : false;
    }

    public function getMissingOtherResourceCredentialScopes()
    {
        $missing_scopes = [];
        foreach ($this->_otherResourceOAuthCredentials as $scope => $credential) {
            if (empty($credential)) {
                $missing_scopes[] = $scope;
            }
        }
        return $missing_scopes;
    }
    
    public function getExpiredResourceCredentialScopes()
    {
        $expired_scopes = [];
        foreach ($this->_otherResourceOAuthCredentials as $scope => $credential) {
            if (!empty($credential)) {
                if ($credential->isExpired()) {
                    $expired_scopes[] = $scope;
                }
            }
        }
        return $expired_scopes;
    }

    public function getLogoutUrl($redirectUri = false)
    {
        $uri = new Uri($this->_microsoftConfiguration->getEndSessionEndpoint());
        $uri = (string) Uri::withQueryValue($uri, 'id_token_hint', (string) $this->_idTokenJWT->getJWT());
        if ($redirectUri) {
            $uri = (string) Uri::withQueryValue($uri, 'post_logout_redirect_uri', (string) $redirectUri);
        }
        return $uri;
    }

    public function haveRefreshToken()
    {
        return isset($this->_refreshToken);
    }
    
    public function isExpired()
    {
        $isIdTokenExpired = $this->getIdTokenJWT()->isExpired();
        $isExpired = time() >= $this->_expires;
        $isOtherCredentialExpired = count($this->getExpiredResourceCredentialScopes()) ? true : false;
        return ($isIdTokenExpired || $isExpired || $isOtherCredentialExpired);
    }

    public function canRefreshToken()
    {
        return $this->haveRefreshToken() && !$this->getRefreshToken()->isExpired();
    }
    
    private function _setAttrByAccessToken($accessToken)
    {
        $idTokenJWTClass = $this->getIdTokenJWTClass();
        $this->_idTokenJWT = new $idTokenJWTClass(
            $this->_microsoftConfiguration,
            ($accessToken->getValues())['id_token'],
            $this->_microsoftConfiguration->getClientId()
        );

        $this->_accessToken = $accessToken->getToken();
        $this->_expires = $accessToken->getExpires() - 3420;
        
        $refresh_token_expires_in = (new \DateTime('23:59'))->getTimestamp() - time();
        if (isset(($accessToken->getValues())['refresh_token_expires_in'])) {
            $refresh_token_expires_in = ($accessToken->getValues())['refresh_token_expires_in'];
        }
        
        if (!empty($accessToken->getRefreshToken())) {
            $this->_refreshToken = new MicrosoftRefreshToken(
                $accessToken->getRefreshToken(),
                $refresh_token_expires_in
            );
        }
    }
}