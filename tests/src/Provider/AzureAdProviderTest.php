<?php

namespace Alancting\OAuth2\OpenId\Client\Test\Provider;

use Alancting\OAuth2\OpenId\Client\Test\Base\AbstractAzureAdTestCase;
use Alancting\OAuth2\OpenId\Client\Provider\AzureAdProvider;
use Mockery as m;

class AzureAdProviderTest extends AbstractAzureAdTestCase
{
    public function testMissingTenant()
    {
        $this->setExpectedException(
            'UnexpectedValueException',
            'Missing tenant'
        );

        $this->_getAzureAdProvider([]);
    }

    public function testMissingTenantId()
    {
        $this->setExpectedException(
            'UnexpectedValueException',
            'Missing tenant_id'
        );

        $this->_getAzureAdProvider([
            'tenant' => $this->mockTenantId,
        ]);
    }

    public function testMissingUserKey()
    {
        $this->setExpectedException(
            'UnexpectedValueException',
            'Missing user_key'
        );

        $this->_getAzureAdProvider([
            'tenant' => $this->mockTenantId,
            'tenant_id' => $this->mockTenantId,
        ]);
    }

    public function testConfigurationNotFound()
    {
        m::close();

        $this->setExpectedException(
            'UnexpectedValueException',
            'Configuration not found'
        );

        $config = m::mock('overload:Alancting\Microsoft\JWT\AzureAd\AzureAdConfiguration');
        $config->shouldReceive('getLoadStatus')
                ->andReturn(['status' => false, 'error' => 'Configuration not found']);

        $this->_getSimpleAzureAdProvider();
    }

    public function testUserKey()
    {
        $provider = $this->_getSimpleAzureAdProvider();
        $this->assertEquals($this->mockUserKey, $provider->getUserKey());
    }

    public function testBaseAuthorizationUrl()
    {
        $provider = $this->_getSimpleAzureAdProvider();
        $this->assertEquals($this->mockAuthorizationBaseUrl, $provider->getBaseAuthorizationUrl());
    }

    public function testGetBaseAccessTokenUrl()
    {
        $provider = $this->_getSimpleAzureAdProvider();

        $params = [];
        $this->assertEquals($this->mockAccessTokenBaseUrl, $provider->getBaseAccessTokenUrl([]));
    }

    public function testResourceOwnerDetailsUrl()
    {
        $provider = $this->_getSimpleAzureAdProvider();
        $mockAccessToken = $this->getMockAccessToken();

        $url = $provider->getResourceOwnerDetailsUrl($mockAccessToken);

        $this->assertUrl([
            'scheme' => 'https',
            'host' => 'graph.microsoft.com',
            'path' => '/oidc/userinfo',
            'query' => 'access_token=mock-access-token',
        ], $url);
    }

    public function testLogoutUrl()
    {
        $provider = $this->_getSimpleAzureAdProvider();

        $url = $provider->getLogoutUrl();
        $uri = parse_url($url);

        $expectedUri = parse_url($this->mockEndSessionBaseUrl);

        $this->assertUrl([
            'scheme' => $expectedUri['scheme'],
            'host' => $expectedUri['host'],
            'path' => $expectedUri['path'],
        ], $url);
    }

    public function testLogoutUrlWithIdToken()
    {
        $provider = $this->_getSimpleAzureAdProvider();

        $idToken = 'mock-id-token';
        $url = $provider->getLogoutUrl($idToken);
        $uri = parse_url($url);

        $expectedUri = parse_url($this->mockEndSessionBaseUrl);

        $this->assertUrl([
            'scheme' => $expectedUri['scheme'],
            'host' => $expectedUri['host'],
            'path' => $expectedUri['path'],
            'query' => sprintf('id_token_hint=%s', $idToken),
        ], $url);
    }

    public function testLogoutUrlWithRedirectUri()
    {
        $provider = $this->_getSimpleAzureAdProvider();

        $redirectUri = 'mock-redirect-uri';
        $url = $provider->getLogoutUrl(null, $redirectUri);

        $expectedUri = parse_url($this->mockEndSessionBaseUrl);

        $this->assertUrl([
            'scheme' => $expectedUri['scheme'],
            'host' => $expectedUri['host'],
            'path' => $expectedUri['path'],
            'query' => sprintf('post_logout_redirect_uri=%s', $redirectUri),
        ], $url);
    }

    public function testLogoutUrlWithIdTokenAndRedirectUri()
    {
        $provider = $this->_getSimpleAzureAdProvider();

        $idToken = 'mock-id-token';
        $redirectUri = 'mock-redirect-uri';
        $url = $provider->getLogoutUrl($idToken, $redirectUri);

        $expectedUri = parse_url($this->mockEndSessionBaseUrl);

        $this->assertUrl([
            'scheme' => $expectedUri['scheme'],
            'host' => $expectedUri['host'],
            'path' => $expectedUri['path'],
            'query' => sprintf('id_token_hint=%s&post_logout_redirect_uri=%s', $idToken, $redirectUri),
        ], $url);
    }

    public function testScopes()
    {
        $provider = $this->_getSimpleAzureAdProvider();
        $scopes = $provider->getScopes();

        $this->assertEquals(3, count($scopes));
        $this->assertContains('openid', $scopes);
        $this->assertContains('microsoft_resource_scopes1', $scopes);
        $this->assertContains('microsoft_resource_scopes2', $scopes);
    }

    public function testMicrosoftResourceScopes()
    {
        $provider = $this->_getSimpleAzureAdProvider();
        $scopes = $provider->getMicrosoftResourceScopes();

        $this->assertEquals(2, count($scopes));
        $this->assertContains('microsoft_resource_scopes1', $scopes);
        $this->assertContains('microsoft_resource_scopes2', $scopes);
    }

    public function testOtherResourceScopes()
    {
        $provider = $this->_getSimpleAzureAdProvider();
        $scopes = $provider->getOtherResourceScopes();

        $this->assertEquals(2, count($scopes));
        $this->assertContains('other_resource_scopes1', $scopes);
        $this->assertContains('other_resource_scopes2', $scopes);
    }

    public function testMicrosoftConfiguration()
    {
        $provider = $this->_getSimpleAzureAdProvider();
        $config = $provider->getMicrosoftConfiguration();
        $this->assertInstanceOf('Alancting\Microsoft\JWT\AzureAd\AzureAdConfiguration', $config);
    }

    public function testDefaultScopes()
    {
        $provider = $this->_getSimpleAzureAdProvider();
        $scopes = $provider->getDefaultScopes();

        $this->assertEquals(1, count($scopes));
        $this->assertContains('openid', $scopes);
    }

    public function testAuthorizationUrl()
    {
        $provider = $this->_getSimpleAzureAdProvider();
        $url = $provider->getAuthorizationUrl();
        $uri = parse_url($url);
        parse_str($uri['query'], $query);

        $this->assertArrayHasKey('client_id', $query);
        $this->assertArrayHasKey('redirect_uri', $query);
        $this->assertArrayHasKey('state', $query);
        $this->assertArrayHasKey('scope', $query);
        $this->assertArrayHasKey('response_type', $query);
        $this->assertArrayHasKey('approval_prompt', $query);
        $this->assertNotNull($provider->getState());
    }

    public function testInvalidGetResourceOwner()
    {
        $this->setExpectedException(
            'League\OAuth2\Client\Provider\Exception\IdentityProviderException',
            'CompactToken parsing failed with error code: 80049217'
        );

        $mockPostResult = [
            'access_token' => 'mock-access-token',
            'authentication_token' => 'mock-authentication-token',
            'code' => 'mock-code',
            'expires_in' => 3600,
            'refresh_token' => 'mock-refresh-token',
            'scope' => 'openid',
            'state' => 'mock-state',
            'token_type' => '',
            'id_token' => 'mock-id-token',
        ];

        $mockUserResult = [
            'error' => [
                'code' => 'InvalidAuthenticationToken',
                'message' => 'CompactToken parsing failed with error code: 80049217',
                'innerError' => [
                    'date' => '2020-11-04T06:34:39',
                    'request-id' => 'mock-request-id',
                    'client-request-id' => 'mock-client-request-id',
                ],
            ],
        ];

        $postResponse = m::mock('Psr\Http\Message\ResponseInterface');
        $postResponse->shouldReceive('getBody')->andReturn(json_encode($mockPostResult));
        $postResponse->shouldReceive('getStatusCode')->andReturn(201);
        $postResponse->shouldReceive('getHeader')->andReturn(['content-type' => 'json']);

        $userResponse = m::mock('Psr\Http\Message\ResponseInterface');
        $userResponse->shouldReceive('getBody')->andReturn(json_encode($mockUserResult));
        $userResponse->shouldReceive('getStatusCode')->andReturn(401);
        $userResponse->shouldReceive('getHeader')->andReturn(['content-type' => 'json']);

        $provider = $this->_getSimpleAzureAdProvider();

        $client = m::mock('GuzzleHttp\ClientInterface');
        $client->shouldReceive('send')
            ->times(2)
            ->andReturn($postResponse, $userResponse);
        $provider->setHttpClient($client);

        $token = $provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);
        $user = $provider->getResourceOwner($token);
    }

    public function testInvalidGetResourceOwnerEmptyErrMessage()
    {
        $this->setExpectedException(
            'League\OAuth2\Client\Provider\Exception\IdentityProviderException',
            'Unauthorized'
        );

        $mockPostResult = [
            'access_token' => 'mock-access-token',
            'authentication_token' => 'mock-authentication-token',
            'code' => 'mock-code',
            'expires_in' => 3600,
            'refresh_token' => 'mock-refresh-token',
            'scope' => 'openid',
            'state' => 'mock-state',
            'token_type' => '',
            'id_token' => 'mock-id-token',
        ];

        $mockUserResult = [
            'error' => [
                'code' => 'InvalidAuthenticationToken',
                'innerError' => [
                    'date' => '2020-11-04T06:34:39',
                    'request-id' => 'mock-request-id',
                    'client-request-id' => 'mock-client-request-id',
                ],
            ],
        ];

        $postResponse = m::mock('Psr\Http\Message\ResponseInterface');
        $postResponse->shouldReceive('getBody')->andReturn(json_encode($mockPostResult));
        $postResponse->shouldReceive('getStatusCode')->andReturn(201);
        $postResponse->shouldReceive('getHeader')->andReturn(['content-type' => 'json']);

        $userResponse = m::mock('Psr\Http\Message\ResponseInterface');
        $userResponse->shouldReceive('getBody')->andReturn(json_encode($mockUserResult));
        $userResponse->shouldReceive('getStatusCode')->andReturn(401);
        $userResponse->shouldReceive('getReasonPhrase')->andReturn('Unauthorized');
        $userResponse->shouldReceive('getHeader')->andReturn(['content-type' => 'json']);

        $provider = $this->_getSimpleAzureAdProvider();

        $client = m::mock('GuzzleHttp\ClientInterface');
        $client->shouldReceive('send')
            ->times(2)
            ->andReturn($postResponse, $userResponse);
        $provider->setHttpClient($client);

        $token = $provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);
        $user = $provider->getResourceOwner($token);
    }

    public function testGetResourceOwner()
    {
        $mockPostResult = [
            'access_token' => 'mock-access-token',
            'authentication_token' => 'mock-authentication-token',
            'code' => 'mock-code',
            'expires_in' => 3600,
            'refresh_token' => 'mock-refresh-token',
            'scope' => 'openid',
            'state' => 'mock-state',
            'token_type' => '',
            'id_token' => 'mock-id-token',
        ];

        $mockUserResult = [
            'sub' => 'mock-user-sub',
            'name' => 'mock-user-name',
            'family_name' => 'mock-user-family-name',
            'given_name' => 'mock-user-given-name',
            'email' => 'mock-user-email',
        ];

        $postResponse = m::mock('Psr\Http\Message\ResponseInterface');
        $postResponse->shouldReceive('getBody')->andReturn(json_encode($mockPostResult));
        $postResponse->shouldReceive('getStatusCode')->andReturn(201);
        $postResponse->shouldReceive('getHeader')->andReturn(['content-type' => 'json']);

        $userResponse = m::mock('Psr\Http\Message\ResponseInterface');
        $userResponse->shouldReceive('getBody')->andReturn(json_encode($mockUserResult));
        $userResponse->shouldReceive('getStatusCode')->andReturn(200);
        $userResponse->shouldReceive('getHeader')->andReturn(['content-type' => 'json']);

        $provider = $this->_getSimpleAzureAdProvider();

        $client = m::mock('GuzzleHttp\ClientInterface');
        $client->shouldReceive('send')
            ->times(2)
            ->andReturn($postResponse, $userResponse);
        $provider->setHttpClient($client);

        $token = $provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);
        $user = $provider->getResourceOwner($token);

        $userArray = $user->toArray();

        $this->assertEquals('mock-user-sub', $user->getId());
        $this->assertEquals('mock-user-sub', $user->getSub());

        $this->assertEquals(5, count($userArray));
        $this->assertContains('mock-user-sub', $userArray['sub']);
        $this->assertContains('mock-user-name', $userArray['name']);
        $this->assertContains('mock-user-family-name', $userArray['family_name']);
        $this->assertContains('mock-user-given-name', $userArray['given_name']);
        $this->assertContains('mock-user-email', $userArray['email']);
    }

    private function _getAzureAdProvider($options)
    {
        return new AzureAdProvider($options);
    }

    private function _getSimpleAzureAdProvider($opts = [])
    {
        $default_opts = [
            'tenant' => $this->mockTenantId,
            'tenant_id' => $this->mockTenantId,
            'user_key' => $this->mockUserKey,
            'clientId' => $this->mockClientId,
            'clientSecret' => $this->mockClientSecret,
            'redirectUri' => 'none',
            'microsoft_resource_scopes' => [
                'microsoft_resource_scopes1',
                'microsoft_resource_scopes2',
            ],
            'other_resource_scopes' => [
                'other_resource_scopes1',
                'other_resource_scopes2',
            ],
        ];

        return $this->_getAzureAdProvider($default_opts);
    }
}