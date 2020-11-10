<?php

namespace Alancting\OAuth2\OpenId\Client\Security\Credential;

use Alancting\OAuth2\OpenId\Client\Security\Token\MicrosoftRefreshToken;
use League\OAuth2\Client\Token\AccessToken;
use \UnexpectedValueException;

abstract class MicrosoftOAuthCredential
{
    abstract protected function getIdTokenJWTClass();
    abstract protected function isSupportConfigurationClass($configuration);

    private $_microsoftConfiguration;

    private $_scope;
    private $_idTokenJWT;
    private $_accessToken;
    private $_expires;
    private $_refreshToken;

    private $_otherResourceOAuthCredentials;

    public function __construct(
        $microsoftConfiguration,
        AccessToken $accessToken,
        $scope,
        array $otherResourceScopes = []
    ) {
        if (!$this->isSupportConfigurationClass($microsoftConfiguration)) {
            throw new UnexpectedValueException('Unsupport Microsoft Configuration Class');
        }

        $this->_microsoftConfiguration = $microsoftConfiguration;
        $this->_scope = is_array($scope) ? implode($scope, ' ') : $scope;

        $this->_setAttrByAccessToken($accessToken);

        $this->_otherResourceOAuthCredentials = [];
        foreach ($otherResourceScopes as $scope) {
            ($this->_otherResourceOAuthCredentials)[$scope] = false;
        }
    }

    public function update($microsoftConfiguration, AccessToken $accessToken)
    {
        if (!$this->isSupportConfigurationClass($microsoftConfiguration)) {
            throw new UnexpectedValueException('Unsupport Microsoft Configuration Class');
        }

        $this->_microsoftConfiguration = $microsoftConfiguration;
        $this->_setAttrByAccessToken($accessToken);
    }

    public function setOtherResourceOAuthCredential(string $scope, MicrosoftOAuthCredential $oAuthCredential)
    {
        ($this->_otherResourceOAuthCredentials)[$scope] = $oAuthCredential;
    }

    public function setOtherResourceOAuthCredentialsByTokens(array $scopeTokens)
    {
        foreach ($scopeTokens as $scope => $token) {
            $this->setOtherResourceOAuthCredential($scope, $this->_getMicrosoftOAuthCredential($token, $scope));
        }
    }

    public function getScope()
    {
        return $this->_scope;
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

    public function getOtherResourceCredential(string $scope)
    {
        return isset(($this->_otherResourceOAuthCredentials)[$scope]) ? ($this->_otherResourceOAuthCredentials)[$scope] : false;
    }

    public function getPendingOtherResourceCredentialScopes()
    {
        $pendingScopes = [];
        foreach ($this->_otherResourceOAuthCredentials as $scope => $credential) {
            if (empty($credential)) {
                $pendingScopes[] = $scope;
            } else {
                if ($credential->isExpired()) {
                    $pendingScopes[] = $scope;
                }
            }
        }

        return $pendingScopes;
    }

    public function getExpiredResourceCredentialScopes()
    {
        $expiredScopes = [];
        foreach ($this->_otherResourceOAuthCredentials as $scope => $credential) {
            if (!empty($credential)) {
                if ($credential->isExpired()) {
                    $expiredScopes[] = $scope;
                }
            }
        }

        return $expiredScopes;
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

    public function isRefreshTokenUsable()
    {
        return $this->haveRefreshToken() && !$this->getRefreshToken()->isExpired();
    }

    private function _setAttrByAccessToken(AccessToken $accessToken)
    {
        $idTokenJWTClass = $this->getIdTokenJWTClass();
        $this->_idTokenJWT = new $idTokenJWTClass(
            $this->_microsoftConfiguration,
            ($accessToken->getValues())['id_token'],
            $this->_microsoftConfiguration->getClientId()
        );

        $this->_accessToken = $accessToken->getToken();
        $this->_expires = $accessToken->getExpires();

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

    private function _getMicrosoftOAuthCredential(AccessToken $accessToken, $scope, array $otherResourceScopes = [])
    {
        $className = get_class($this);

        return new $className($this->_microsoftConfiguration, $accessToken, $scope, $otherResourceScopes);
    }
}