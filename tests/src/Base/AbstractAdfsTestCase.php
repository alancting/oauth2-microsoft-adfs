<?php

namespace Alancting\OAuth2\OpenId\Client\Test\Base;

use Mockery as m;

abstract class AbstractAdfsTestCase extends AbstractTestCase
{
    const MOCK_HOST_NAME = 'mock-host-name.com';
    protected $mockClientId = 'mock_client_id';
    protected $mockClientSecret = 'mock_secret';
    protected $mockUserKey = 'unique_name';

    protected $mockHostname = self::MOCK_HOST_NAME;
    protected $mockAuthorizationBaseUrl = 'https://' . self::MOCK_HOST_NAME . '/adfs/oauth2/authorize/';
    protected $mockAccessTokenBaseUrl = 'https://' . self::MOCK_HOST_NAME . '/adfs/oauth2/token/';
    protected $mockResourceOwnerDetailsBaseUrl = 'https://' . self::MOCK_HOST_NAME . '/adfs/userinfo';
    protected $mockEndSessionBaseUrl = 'https://' . self::MOCK_HOST_NAME . '/adfs/oauth2/logout';

    protected function getProviderClassName()
    {
        return 'Alancting\OAuth2\OpenId\Client\Provider\AdfsProvider';
    }

    protected function getClientClassName()
    {
        return 'Alancting\OAuth2\OpenId\Client\Client\AdfsClient';
    }

    protected function geIdTokenJWTClassName()
    {
        return 'Alancting\Microsoft\JWT\Adfs\AdfsIdTokenJWT';
    }

    protected function geCredentialClassName()
    {
        return 'Alancting\OAuth2\OpenId\Client\Security\Credential\AdfsOAuthCredential';
    }

    protected function getMockCredentialClassName()
    {
        return 'Alancting\OAuth2\OpenId\Client\Security\Credential\AdfsOAuthCredential';
    }

    protected function getMockMicrosoftConfiguration()
    {
        $this->configuration = m::mock('overload:' . 'Alancting\Microsoft\JWT\Adfs\AdfsConfiguration');
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