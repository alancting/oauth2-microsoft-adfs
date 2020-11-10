<?php

namespace Alancting\OAuth2\OpenId\Client\Test\Client;

use Alancting\OAuth2\OpenId\Client\Test\Base\AbstractAzureAdTestCase;
use Alancting\OAuth2\OpenId\Client\Provider\AzureAdProvider;
use Alancting\OAuth2\OpenId\Client\Client\AzureAdClient;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Mockery as m;

class AzureAdClientTest extends AbstractAzureAdTestCase
{
    protected $provider;
    protected $request;

    protected function setUp(): void
    {
        parent::setUp();

        $options = [
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
        $this->provider = new AzureAdProvider($options);
        $this->request = new Request();
    }

    public function testGetClientKey()
    {
        $client = $this->_getMockClient($this->request);

        $this->assertEquals('azure_ad_oauth', $client->getClientKey());
    }

    public function testStartAuthorization()
    {
        $client = $this->_getMockClient($this->request);

        $response = $client->startAuthorization($this->request);
        $this->assertInstanceOf(
            'Symfony\Component\HttpFoundation\RedirectResponse',
            $response
        );
    }

    public function testFetchPendingOtherResourceAccessTokensByRefreshTokenByCredentialNoCrential()
    {
        $client = $this->_getMockClient($this->request);

        $credential = null;
        $tokens = $client->fetchPendingOtherResourceAccessTokensByRefreshTokenByCredential($credential);
        $this->assertEquals(0, count($tokens));
    }

    public function testFetchPendingOtherResourceAccessTokensByRefreshTokenByCredentialNoPending()
    {
        $client = $this->_getMockClient($this->request);

        $postResponse = $this->_getMockGetAccessTokenHttpResponse();

        $restClient = m::mock('GuzzleHttp\ClientInterface');
        $restClient->shouldReceive('send')
                    ->times(0)
                    ->andReturn($postResponse);
        $client->getOAuth2Provider()->setHttpClient($restClient);

        $credential = m::mock('Alancting\OAuth2\OpenId\Client\Security\Credential\AzureAdOAuthCredential');
        $credential->shouldReceive('getPendingOtherResourceCredentialScopes')
                    ->andReturn([]);
        $credential->shouldReceive('getRefreshToken')
                    ->andReturn(null);

        $tokens = $client->fetchPendingOtherResourceAccessTokensByRefreshTokenByCredential($credential);
        $this->assertEquals(0, count($tokens));
    }

    public function testFetchPendingOtherResourceAccessTokensByRefreshTokenByCredential()
    {
        $client = $this->_getMockClient($this->request);

        $postResponse = $this->_getMockGetAccessTokenHttpResponse();

        $restClient = m::mock('GuzzleHttp\ClientInterface');
        $restClient->shouldReceive('send')
                    ->times(1)
                    ->andReturn($postResponse);
        $client->getOAuth2Provider()->setHttpClient($restClient);

        $refreshToken = $this->_getMockRefreshToken();

        $credential = m::mock('Alancting\OAuth2\OpenId\Client\Security\Credential\AzureAdOAuthCredential');
        $credential->shouldReceive('getPendingOtherResourceCredentialScopes')
                    ->andReturn(['scope1']);
        $credential->shouldReceive('getRefreshToken')
                    ->andReturn($refreshToken);

        $tokens = $client->fetchPendingOtherResourceAccessTokensByRefreshTokenByCredential($credential);

        $this->assertEquals(1, count($tokens));
        $this->assertArrayHasKey('scope1', $tokens);
        $this->assertInstanceOf('League\OAuth2\Client\Token\AccessToken', $tokens['scope1']);
    }

    public function testFetchAccessTokenByRefreshToken()
    {
        $client = $this->_getMockClient($this->request);

        $postResponse = $this->_getMockGetAccessTokenHttpResponse();

        $restClient = m::mock('GuzzleHttp\ClientInterface');
        $restClient->shouldReceive('send')
                    ->times(1)
                    ->andReturn($postResponse);
        $client->getOAuth2Provider()->setHttpClient($restClient);

        $refreshToken = $this->_getMockRefreshToken();

        $token = $client->fetchAccessTokenByRefreshToken($refreshToken);
        $this->assertInstanceOf('League\OAuth2\Client\Token\AccessToken', $token);
    }

    public function testGetOAuthCredentialBySecurityWithoutLogin()
    {
        $security = $this->_getSecurity()->reveal();
        $client = $this->_getMockClient($this->request);
        $oauthCredential = $client->getOAuthCredentialBySecurity($security);

        $this->assertFalse($oauthCredential);
    }

    public function testGetOAuthCredentialBySecurity()
    {
        $security = $this->_getLoggedInSecurity()->reveal();
        $client = $this->_getMockClient($this->request);
        $oauthCredential = $client->getOAuthCredentialBySecurity($security);

        $this->assertInstanceOf(
            'Alancting\OAuth2\OpenId\Client\Security\Credential\AzureAdOAuthCredential',
            $oauthCredential);
    }

    public function testGetMicrosoftConfiguration()
    {
        $client = $this->_getMockClient($this->request);
        $configuration = $client->getMicrosoftConfiguration();
        $this->assertInstanceOf(
            'Alancting\Microsoft\JWT\AzureAd\AzureAdConfiguration',
            $configuration);
    }

    public function testGetLogoutUrlWithoutLogin()
    {
        $client = $this->_getMockClient($this->request);
        $logourUrl = $client->getLogoutUrl();

        $this->assertUrl(
            [
                'scheme' => 'https',
                'host' => 'login.microsoftonline.com',
                'path' => sprintf('/%s/oauth2/v2.0/logout', $this->mockTenantId),
            ], $client->getLogoutUrl()
        );
    }

    public function testGetLogoutUrl()
    {
        $client = $this->_getLoggedinMockClient($this->request);

        $this->assertUrl(
            [
                'scheme' => 'https',
                'host' => 'login.microsoftonline.com',
                'path' => sprintf('/%s/oauth2/v2.0/logout', $this->mockTenantId),
                'query' => 'id_token_hint=mock-id-token',
            ], $client->getLogoutUrl()
        );
    }

    public function testGetOAuthCredentialWithoutLogin()
    {
        $client = $this->_getMockClient($this->request);
        $oauthCredential = $client->getOAuthCredential();

        $this->assertFalse($oauthCredential);
    }

    public function testGetOAuthCredential()
    {
        $client = $this->_getLoggedinMockClient($this->request);
        $oauthCredential = $client->getOAuthCredential();

        $this->assertInstanceOf(
            'Alancting\OAuth2\OpenId\Client\Security\Credential\AzureAdOAuthCredential',
            $oauthCredential);
    }

    private function _getMockClient($request)
    {
        $session = $this->prophesize('Symfony\Component\HttpFoundation\Session\SessionInterface');

        $security = $this->_getSecurity();
        $request->setSession($session->reveal());

        $mockRequest = m::mock($request);
        $requestStack = new RequestStack();
        $requestStack->push($mockRequest);

        return new AzureAdClient($this->provider, $requestStack, $security->reveal());
    }

    private function _getLoggedinMockClient($request)
    {
        $session = $this->prophesize('Symfony\Component\HttpFoundation\Session\SessionInterface');

        $security = $this->_getLoggedInSecurity();
        $request->setSession($session->reveal());

        $mockRequest = m::mock($request);
        $requestStack = new RequestStack();
        $requestStack->push($mockRequest);

        return new AzureAdClient($this->provider, $requestStack, $security->reveal());
    }

    private function _getSecurity()
    {
        $securityToken = $this->prophesize('Symfony\Component\Security\Core\Authentication\Token\TokenInterface');
        $securityUser = $this->prophesize('Symfony\Component\Security\Core\User\UserInterface');
        $security = $this->prophesize('Symfony\Component\Security\Core\Security');
        $security->getToken()->willReturn(null);
        $security->getUser()->willReturn(null);

        return $security;
    }

    private function _getLoggedInSecurity()
    {
        $refreshToken = $this->_getMockRefreshToken();
        $idToken = $this->getMockIdTokenJWT();
        $credential = m::mock('Alancting\OAuth2\OpenId\Client\Security\Credential\AzureAdOAuthCredential');
        $credential->shouldReceive('getRefreshToken')
                    ->andReturn($refreshToken);
        $credential->shouldReceive('getIdTokenJWT')
                    ->andReturn($idToken);

        $securityToken = $this->prophesize('Symfony\Component\Security\Core\Authentication\Token\TokenInterface');
        $securityToken->getAttributes()->willReturn(['azure_ad_oauth' => $credential]);
        $securityUser = $this->prophesize('Symfony\Component\Security\Core\User\UserInterface');
        $security = $this->prophesize('Symfony\Component\Security\Core\Security');
        $security->getToken()->willReturn($securityToken);
        $security->getUser()->willReturn($securityUser);

        return $security;
    }

    private function _getMockGetAccessTokenHttpResponse()
    {
        $body = [
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

        $response = m::mock('Psr\Http\Message\ResponseInterface');
        $response->shouldReceive('getBody')->andReturn(json_encode($body));
        $response->shouldReceive('getStatusCode')->andReturn(201);
        $response->shouldReceive('getHeader')->andReturn(['content-type' => 'json']);

        return $response;
    }

    private function _getMockRefreshToken()
    {
        $refreshToken = m::mock('Alancting\OAuth2\OpenId\Client\Security\Token\MicrosoftRefreshToken');
        $refreshToken->shouldReceive('getToken')->andReturn('refresh-token');

        return $refreshToken;
    }
}