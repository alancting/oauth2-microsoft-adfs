<?php

namespace Alancting\OAuth2\OpenId\Client\Test\Base;

use Mockery as m;

abstract class AbstractAzureAdTestCase extends AbstractTestCase
{
    const MOCK_TENANT_ID = 'mock-tenant-id';
    protected $mockClientId = 'mock-client-id';
    protected $mockClientSecret = 'mock_secret';
    protected $mockUserKey = 'upn';

    protected $mockTenantId = self::MOCK_TENANT_ID;
    protected $mockAuthorizationBaseUrl = 'https://login.microsoftonline.com/' . self::MOCK_TENANT_ID . '/oauth2/v2.0/authorize';
    protected $mockAccessTokenBaseUrl = 'https://login.microsoftonline.com/' . self::MOCK_TENANT_ID . '/oauth2/v2.0/token';
    protected $mockResourceOwnerDetailsBaseUrl = 'https://graph.microsoft.com/oidc/userinfo';
    protected $mockEndSessionBaseUrl = 'https://login.microsoftonline.com/' . self::MOCK_TENANT_ID . '/oauth2/v2.0/logout';

    protected function getProviderClassName()
    {
        return 'Alancting\OAuth2\OpenId\Client\Provider\AzureAdProvider';
    }

    protected function getClientClassName()
    {
        return 'Alancting\OAuth2\OpenId\Client\Client\AzureAdClient';
    }

    protected function geIdTokenJWTClassName()
    {
        return 'Alancting\Microsoft\JWT\AzureAd\AzureAdIdTokenJWT';
    }

    protected function geCredentialClassName()
    {
        return 'Alancting\OAuth2\OpenId\Client\Security\Credential\AzureAdOAuthCredential';
    }

    protected function getMockCredentialClassName()
    {
        return 'Alancting\OAuth2\OpenId\Client\Security\Credential\AzureAdOAuthCredential';
    }

    protected function getMockMicrosoftConfiguration()
    {
        $this->configuration = m::mock('overload:' . 'Alancting\Microsoft\JWT\AzureAd\AzureAdConfiguration');
        $this->configuration->shouldReceive('getAuthorizationEndpoint')
                ->andReturn($this->mockAuthorizationBaseUrl);
        $this->configuration->shouldReceive('getTokenEndpoint')
                ->andReturn($this->mockAccessTokenBaseUrl);
        $this->configuration->shouldReceive('getUserInfoEndpoint')
                ->andReturn($this->mockResourceOwnerDetailsBaseUrl);
        $this->configuration->shouldReceive('getEndSessionEndpoint')
                ->andReturn($this->mockEndSessionBaseUrl);
        $this->configuration->shouldReceive('getLoadStatus')
                ->andReturn(['status' => true]);
        $this->configuration->shouldReceive('getClientId')
                ->andReturn($this->mockClientId);
    }
}