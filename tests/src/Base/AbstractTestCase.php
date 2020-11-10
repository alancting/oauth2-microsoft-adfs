<?php

namespace Alancting\OAuth2\OpenId\Client\Test\Base;

use PHPUnit\Framework\TestCase;
use Mockery as m;

abstract class AbstractTestCase extends TestCase
{
    abstract protected function getProviderClassName();
    abstract protected function getClientClassName();
    abstract protected function geIdTokenJWTClassName();
    abstract protected function geCredentialClassName();
    abstract protected function getMockCredentialClassName();
    abstract protected function getMockMicrosoftConfiguration();

    protected $configuration;
    protected $idTokenJWT;

    protected function setUp(): void
    {
        $this->getMockMicrosoftConfiguration();
        $this->idTokenJWT = $this->getMockIdTokenJWT();
    }

    public function tearDown(): void
    {
        m::close();
        parent::tearDown();
    }

    protected function assertOAuthUser($expected, $checkOAuthUser)
    {
        $this->assertInstanceOf(
          'Alancting\OAuth2\OpenId\Client\Security\User\MicrosoftOAuthUser',
          $checkOAuthUser
        );

        $this->assertEquals($expected['username'], $checkOAuthUser->getUsername());
        $this->assertEquals($expected['roles'], $checkOAuthUser->getRoles());
        $this->assertEquals('', $checkOAuthUser->getPassword());
        $this->assertEquals(null, $checkOAuthUser->getSalt());
    }

    protected function assertOAuthCredential($expected, $checkCredential)
    {
        $this->assertInstanceOf(
            $this->geCredentialClassName(),
            $checkCredential
        );

        $this->assertEquals($expected['scope'], $checkCredential->getScope());
        $this->assertIdTokenJWT($expected['id_token_jwt'], $checkCredential->getIdTokenJWT());
        $this->assertAccessToken($expected['access_token'], $checkCredential->getAccessToken());
        $this->assertRefreshToken($expected['refresh_token'], $checkCredential->getRefreshToken());

        $this->assertEquals($expected['num_other_resources'], count($checkCredential->getOtherResourceCredentials()));
        $this->assertEquals($expected['num_pending_other_resources'], count($checkCredential->getPendingOtherResourceCredentialScopes()));
        $this->assertEquals($expected['num_expired_other_resources'], count($checkCredential->getExpiredResourceCredentialScopes()));
    }

    protected function assertIdTokenJWT($expected, $checkIdTokenJWT)
    {
        $this->assertEquals($expected['is_expired'], $checkIdTokenJWT->isExpired());
        $this->assertEquals($expected['payload'], $checkIdTokenJWT->getPayload());
        $this->assertEquals($expected['jwt'], $checkIdTokenJWT->getJWT());
    }

    protected function assertAccessToken($expectedAccessToken, $checkAccessToken)
    {
        $this->assertEquals($expectedAccessToken, $checkAccessToken);
    }

    protected function assertRefreshToken($expected, $checkRefreshToken)
    {
        if (empty($checkRefreshToken)) {
            $this->assertEquals($expected, $checkRefreshToken);
        } else {
            $this->assertEquals($expected['token'], $checkRefreshToken->getToken());
            $this->assertEquals($expected['is_expired'], $checkRefreshToken->isExpired());
        }
    }

    protected function assertUrl($expected, $checkUrl)
    {
        $checkUri = parse_url($checkUrl);

        $this->assertEquals($expected['scheme'], $checkUri['scheme']);
        $this->assertEquals($expected['host'], $checkUri['host']);
        $this->assertEquals($expected['path'], $checkUri['path']);

        if (isset($expected['query'])) {
            $this->assertEquals($expected['query'], $checkUri['query']);
        }
    }

    protected function getMockProvider($otherResourceScopes = [])
    {
        $provider = m::mock($this->getProviderClassName());
        $provider
          ->shouldReceive('getUserKey')
          ->andReturn('mock-user-key');
        $provider
          ->shouldReceive('getScopes')
          ->andReturn('openid');
        $provider
          ->shouldReceive('getOtherResourceScopes')
          ->andReturn($otherResourceScopes);

        return $provider;
    }

    protected function getMockClient($mockOauthCredential, $mockProvider, $mockAccessTokens = [], $mockOtherResourcesAccessTokens = [])
    {
        if (!is_array($mockAccessTokens) && !empty($mockAccessTokens)) {
            $mockAccessTokens = [$mockAccessTokens];
        }

        if (empty($mockAccessTokens)) {
            $mockAccessTokens = [$this->getMockAccessToken()];
        }

        $mockRedirectResponse = $this->prophesize('Symfony\Component\HttpFoundation\RedirectResponse');

        $client = m::mock($this->getClientClassName());
        $client
          ->shouldReceive('getOAuthCredentialBySecurity')
          ->andReturn($mockOauthCredential);
        $client
          ->shouldReceive('getOAuth2Provider')
          ->andReturn($mockProvider);
        $client
          ->shouldReceive('getAccessToken')
          ->andReturnValues($mockAccessTokens);
        $client
          ->shouldReceive('getMicrosoftConfiguration')
          ->andReturn($this->configuration);
        $client
          ->shouldReceive('fetchPendingOtherResourceAccessTokensByRefreshTokenByCredential')
          ->andReturn($mockOtherResourcesAccessTokens);
        $client
          ->shouldReceive('fetchAccessTokenByRefreshToken')
          ->andReturnValues($mockAccessTokens);
        $client
          ->shouldReceive('startAuthorization')
          ->andReturn($mockRedirectResponse->reveal());
        $client
          ->shouldReceive('getClientKey')
          ->andReturn('mock-client-key');

        return $client;
    }

    protected function getMockCredential($opt = [])
    {
        /**
         * $opts can be
         * - mock_is_expired
         * - mock_is_refresh_token_usable
         */
        if (!isset($opt['mock_is_expired'])) {
            $opt['mock_is_expired'] = false;
        }

        if (!isset($opt['mock_is_refresh_token_usable'])) {
            $opt['mock_is_refresh_token_usable'] = false;
        }

        $mockCredential = m::mock($this->getMockCredentialClassName());
        $mockCredential
          ->shouldReceive('isExpired')
          ->andReturn($opt['mock_is_expired']);
        $mockCredential
          ->shouldReceive('isRefreshTokenUsable')
          ->andReturn($opt['mock_is_refresh_token_usable']);
        $mockCredential
          ->shouldReceive('getIdTokenJWT')
          ->andReturn($this->idTokenJWT);

        return $mockCredential;
    }

    protected function getMockAccessToken($opts = [])
    {
        /**
         * $opts can be
         * - mock_token
         * - mock_expires
         * - mock_refresh_token_expires_in
         * - mock_refresh_token
         */
        $values = [
            'id_token' => isset($opts['mock_id_token']) ? $opts['mock_id_token'] : 'mock-id-token',
        ];

        if (isset($opts['scope'])) {
            $values['scope'] = $opts['scope'];
        }

        if (isset($opts['mock_refresh_token_expires_in'])) {
            $values['refresh_token_expires_in'] = $opts['mock_refresh_token_expires_in'];
        }

        $token = m::mock('League\OAuth2\Client\Token\AccessToken');
        $token
          ->shouldReceive('getToken')
          ->andReturn(
            isset($opts['mock_token']) ? $opts['mock_token'] : 'mock-access-token');
        $token
          ->shouldReceive('getValues')
          ->andReturn($values);
        $token
          ->shouldReceive('getExpires')
          ->andReturn(isset($opts['mock_expires']) ? $opts['mock_expires'] : time()+3600);
        $token
          ->shouldReceive('getRefreshToken')
          ->andReturn(isset($opts['mock_refresh_token']) ? $opts['mock_refresh_token'] : null);

        return $token;
    }

    protected function getMockIdTokenJWT($expired = false)
    {
        $mockIdTokenJWT = m::mock('overload:' . $this->geIdTokenJWTClassName())->makePartial();
        $mockIdTokenJWT
          ->shouldReceive('getPayload')
          ->andReturn([
              'mock-id-token-payload-attr1' => 'mock-id-token-payload-value1',
              'mock-id-token-payload-attr2' => 'mock-id-token-payload-value2',
              'mock-id-token-payload-attr3' => 'mock-id-token-payload-value3',
          ]);
        $mockIdTokenJWT
          ->shouldReceive('getJWT')
          ->andReturn('mock-id-token');
        $mockIdTokenJWT
          ->shouldReceive('get')
          ->with('mock-user-key')
          ->andReturn('mock-user-name-from-id-token');
        $mockIdTokenJWT
          ->shouldReceive('isExpired')
          ->andReturn($expired);

        return $mockIdTokenJWT;
    }

    protected function setExpectedException($exceptionName, $message = '', $code = null)
    {
        if (method_exists($this, 'expectException')) {
            $this->expectException($exceptionName);
            if (!empty($message)) {
                $this->expectExceptionMessage($message);
            }
        } else {
            parent::setExpectedException($exceptionName, $message, $code);
        }
    }

    protected function getDefaultExpectedCredential()
    {
        return [
            'scope' => 'openid',
            'id_token_jwt' => [
                'is_expired' => false,
                'payload' => [
                    'mock-id-token-payload-attr1' => 'mock-id-token-payload-value1',
                    'mock-id-token-payload-attr2' => 'mock-id-token-payload-value2',
                    'mock-id-token-payload-attr3' => 'mock-id-token-payload-value3',
                ],
                'jwt' => 'mock-id-token',
            ],
            'access_token' => 'mock-access-token',
            'refresh_token' => null,
            'num_other_resources' => 0,
            'num_pending_other_resources' => 0,
            'num_expired_other_resources' => 0,
        ];
    }
}