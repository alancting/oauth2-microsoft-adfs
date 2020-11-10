<?php

namespace Alancting\OAuth2\OpenId\Client\Test\Security\Credential;

use Alancting\OAuth2\OpenId\Client\Test\Base\AbstractAzureAdTestCase;
use Alancting\OAuth2\OpenId\Client\Security\Credential\AzureAdOAuthCredential;
use Mockery as m;

class AzureAdOAuthCredentialTest extends AbstractAzureAdTestCase
{
    public function testInvalidConstructor()
    {
        $this->setExpectedException(
            'UnexpectedValueException',
            'Unsupport Microsoft Configuration Class'
        );

        $invalidConfiguration = $this->_getInvalidMockConfiguration();
        $oAuthCredential = $this->_getOAuthCredential(['configuration'=>$invalidConfiguration]);
    }

    public function testUpdateInvalidArg()
    {
        $this->setExpectedException(
            'UnexpectedValueException',
            'Unsupport Microsoft Configuration Class'
        );

        $oAuthCredential = $this->_getOAuthCredential();
        $expectedCredential = $this->getDefaultExpectedCredential();
        $this->assertOAuthCredential($expectedCredential, $oAuthCredential);

        $accessToken = $this->getMockAccessToken();
        $invalidConfiguration = $this->_getInvalidMockConfiguration();
        $oAuthCredential->update($invalidConfiguration, $accessToken);
    }

    public function testUpdate()
    {
        $oAuthCredential = $this->_getOAuthCredential();
        $expectedCredential = $this->getDefaultExpectedCredential();
        $this->assertOAuthCredential($expectedCredential, $oAuthCredential);

        $newAccessToken = $this->getMockAccessToken(['mock_token' => 'updated-mock-access-token']);
        $oAuthCredential->update($this->configuration, $newAccessToken);

        $expectedCredential['access_token'] = 'updated-mock-access-token';
        $this->assertOAuthCredential($expectedCredential, $oAuthCredential);
    }

    public function testSetOtherResourceOAuthCredential()
    {
        $oAuthCredential = $this->_getOAuthCredential([
            'other_resource_scopes' => [
                'other_resource_scope1', 'other_resource_scope2',
            ],
        ]);

        $otherResourceOauthCredential = $this->_getOAuthCredential([
            'scope' => 'other_resource_scope1',
        ]);

        $oAuthCredential->setOtherResourceOAuthCredential('other_resource_scope1', $otherResourceOauthCredential);

        $expectedCredential = $this->getDefaultExpectedCredential();
        $expectedCredential['scope'] = 'other_resource_scope1';
        $this->assertOAuthCredential($expectedCredential, $oAuthCredential->getOtherResourceCredential('other_resource_scope1'));
    }

    public function testSetOtherResourceOAuthCredentialsByTokens()
    {
        $oAuthCredential = $this->_getOAuthCredential([
            'other_resource_scopes' => [
                'other_resource_scope1', 'other_resource_scope2',
            ],
        ]);

        $oAuthCredential->setOtherResourceOAuthCredentialsByTokens(
            [
                'other_resource_scope1' => $this->getMockAccessToken(),
                'other_resource_scope2' =>  $this->getMockAccessToken(),
            ]);

        $expectedCredential1 = $this->getDefaultExpectedCredential();
        $expectedCredential1['scope'] = 'other_resource_scope1';

        $expectedCredential2 = $this->getDefaultExpectedCredential();
        $expectedCredential2['scope'] = 'other_resource_scope2';

        $this->assertOAuthCredential($expectedCredential1, $oAuthCredential->getOtherResourceCredential('other_resource_scope1'));
        $this->assertOAuthCredential($expectedCredential2, $oAuthCredential->getOtherResourceCredential('other_resource_scope2'));
    }

    public function testGetRefreshToken()
    {
        $accessToken = $this->getMockAccessToken(
            ['mock_refresh_token' => 'mock-refresh-token']);

        $oAuthCredential = $this->_getOAuthCredential([
            'access_token' => $accessToken,
        ]);

        $expectedCredential = $this->getDefaultExpectedCredential();
        $expectedCredential['refresh_token'] = [
            'token' => 'mock-refresh-token',
            'is_expired' => false,
        ];
        $this->assertOAuthCredential($expectedCredential, $oAuthCredential);
    }

    public function testOtherResourceCredentials()
    {
        $oAuthCredential = $this->_getOAuthCredential([
            'other_resource_scopes' => [
                'other_resource_scope1', 'other_resource_scope2',
            ],
        ]);

        $expectedCredential = $this->getDefaultExpectedCredential();
        $expectedCredential['num_other_resources'] = 2;
        $expectedCredential['num_pending_other_resources'] = 2;

        $this->assertOAuthCredential($expectedCredential, $oAuthCredential);
        $this->assertArrayHasKey('other_resource_scope1', $oAuthCredential->getOtherResourceCredentials());
        $this->assertArrayHasKey('other_resource_scope2', $oAuthCredential->getOtherResourceCredentials());
    }

    public function testOtherResourceCredentialScopesOneValidResourceCredential()
    {
        $oAuthCredential = $this->_getOAuthCredential([
            'other_resource_scopes' => [
                'other_resource_scope1', 'other_resource_scope2',
            ],
        ]);

        $oAuthCredential->setOtherResourceOAuthCredentialsByTokens([
            'other_resource_scope1' => $this->getMockAccessToken(),
        ]);

        $expectedCredential = $this->getDefaultExpectedCredential();
        $expectedCredential['num_other_resources'] = 2;
        $expectedCredential['num_pending_other_resources'] = 1;

        $this->assertOAuthCredential($expectedCredential, $oAuthCredential);
        $this->assertContains('other_resource_scope2', $oAuthCredential->getPendingOtherResourceCredentialScopes());
    }

    public function testOtherResourceCredentialScopesAllValidResourceCredential()
    {
        $oAuthCredential = $this->_getOAuthCredential([
            'other_resource_scopes' => [
                'other_resource_scope1', 'other_resource_scope2',
            ],
        ]);

        $oAuthCredential->setOtherResourceOAuthCredentialsByTokens([
            'other_resource_scope1' => $this->getMockAccessToken(),
            'other_resource_scope2' => $this->getMockAccessToken(),
        ]);

        $expectedCredential = $this->getDefaultExpectedCredential();
        $expectedCredential['num_other_resources'] = 2;
        $expectedCredential['num_pending_other_resources'] = 0;

        $this->assertOAuthCredential($expectedCredential, $oAuthCredential);
    }

    public function testOtherResourceCredentialScopesOneExpiredResourceCredential()
    {
        $oAuthCredential = $this->_getOAuthCredential([
            'other_resource_scopes' => [
                'other_resource_scope1', 'other_resource_scope2',
            ],
        ]);

        $oAuthCredential->setOtherResourceOAuthCredentialsByTokens([
            'other_resource_scope1' => $this->getMockAccessToken(['mock_expires' => 0]),
            'other_resource_scope2' => $this->getMockAccessToken(),
        ]);

        $expectedCredential = $this->getDefaultExpectedCredential();
        $expectedCredential['num_other_resources'] = 2;
        $expectedCredential['num_pending_other_resources'] = 1;
        $expectedCredential['num_expired_other_resources'] = 1;

        $this->assertOAuthCredential($expectedCredential, $oAuthCredential);
        $this->assertContains('other_resource_scope1', $oAuthCredential->getPendingOtherResourceCredentialScopes());
        $this->assertContains('other_resource_scope1', $oAuthCredential->getExpiredResourceCredentialScopes());
    }

    public function testOtherResourceCredentialScopesNoExpired()
    {
        $oAuthCredential = $this->_getOAuthCredential([
            'other_resource_scopes' => [
                'other_resource_scope1', 'other_resource_scope2',
            ],
        ]);

        $oAuthCredential->setOtherResourceOAuthCredentialsByTokens([
            'other_resource_scope1' => $this->getMockAccessToken(),
            'other_resource_scope2' => $this->getMockAccessToken(),
        ]);

        $expectedCredential = $this->getDefaultExpectedCredential();
        $expectedCredential['num_other_resources'] = 2;

        $this->assertOAuthCredential($expectedCredential, $oAuthCredential);
    }

    public function testHaveRefreshTokenWithNoRefreshToken()
    {
        $oAuthCredential = $this->_getOAuthCredential([
            'other_resource_scopes' => [
                'other_resource_scope1', 'other_resource_scope2',
            ],
        ]);
        $this->assertFalse($oAuthCredential->haveRefreshToken());
    }

    public function testHaveRefreshTokenWithRefreshToken()
    {
        $accessToken = $this->getMockAccessToken(['mock_refresh_token' => 'mock-refresh-token']);
        $oAuthCredential = $this->_getOAuthCredential([
            'access_token' => $accessToken,
        ]);

        $this->assertTrue($oAuthCredential->haveRefreshToken());
    }

    public function testIsExpiredNoExpiredNoOtherResource()
    {
        $oAuthCredential = $this->_getOAuthCredential();
        $this->assertFalse($oAuthCredential->isExpired());
    }

    public function testIsExpiredNoExpired()
    {
        $oAuthCredential = $this->_getOAuthCredential();
        $this->assertFalse($oAuthCredential->isExpired());
    }

    public function testIsExpiredOnlyIdTokenExpired()
    {
        m::close();

        $this->idTokenJWT = $this->getMockIdTokenJWT(true);

        $oAuthCredential = $this->_getOAuthCredential();
        $this->assertTrue($oAuthCredential->isExpired());
    }

    public function testIsExpiredOnlyAccessTokenExpired()
    {
        $accessToken = $this->getMockAccessToken(['mock_expires' => 0]);
        $oAuthCredential = $this->_getOAuthCredential([
            'access_token' => $accessToken,
        ]);

        $this->assertTrue($oAuthCredential->isExpired());
    }

    public function testIsExpiredOnlyOtherResourceExpired()
    {
        $oAuthCredential = $this->_getOAuthCredential([
            'other_resource_scopes' => [
                'other_resource_scope1', 'other_resource_scope2',
            ],
        ]);

        $oAuthCredential->setOtherResourceOAuthCredentialsByTokens([
            'other_resource_scope1' => $this->getMockAccessToken(['mock_expires' => 0]),
            'other_resource_scope2' => $this->getMockAccessToken(),
        ]);

        $this->assertTrue($oAuthCredential->isExpired());
    }

    public function testIsExpiredAllResourceExpired()
    {
        m::close();
        $this->idTokenJWT = $this->getMockIdTokenJWT(true);

        $accessToken = $this->getMockAccessToken(['mock_expires' => 0]);
        $oAuthCredential = $this->_getOAuthCredential([
            'access_token' => $accessToken,
            'other_resource_scopes' => [
                'other_resource_scope1', 'other_resource_scope2',
            ],
        ]);

        $oAuthCredential->setOtherResourceOAuthCredentialsByTokens([
            'other_resource_scope1' => $this->getMockAccessToken(['mock_expires' => 0]),
            'other_resource_scope2' => $this->getMockAccessToken(['mock_expires' => 0]),
        ]);

        $this->assertTrue($oAuthCredential->isExpired());
    }

    public function testIsRefreshTokenUsableNoRefreshToken()
    {
        $oAuthCredential = $this->_getOAuthCredential();
        $this->assertFalse($oAuthCredential->isRefreshTokenUsable());
    }

    public function testIsRefreshTokenUsableRefreshTokenAndExpired()
    {
        $accessToken = $this->getMockAccessToken(
            ['mock_refresh_token' => 'mock-refresh-token', 'mock_refresh_token_expires_in' => 0]);

        $oAuthCredential = $this->_getOAuthCredential([
            'access_token' => $accessToken,
        ]);

        sleep(1);

        $this->assertFalse($oAuthCredential->isRefreshTokenUsable());
    }

    public function testIsRefreshTokenUsableRefreshTokenAndNotExpired()
    {
        $accessToken = $this->getMockAccessToken(
            ['mock_refresh_token' => 'mock-refresh-token', 'mock_refresh_token_expires_in' => 3600]);
        $oAuthCredential = $this->_getOAuthCredential([
            'access_token' => $accessToken,
        ]);

        $this->assertTrue($oAuthCredential->isRefreshTokenUsable());
    }

    public function testIsRefreshTokenUsable()
    {
        $accessToken = $this->getMockAccessToken(
            ['mock_refresh_token' => 'mock-refresh-token']);
        $oAuthCredential = $this->_getOAuthCredential([
            'access_token' => $accessToken,
        ]);

        $this->assertTrue($oAuthCredential->isRefreshTokenUsable());
    }

    private function _getInvalidMockConfiguration()
    {
        $configuration = m::mock('alias:Alancting\Microsoft\JWT\Adfs\AdfsConfiguration');

        return $configuration;
    }

    private function _getOAuthCredential($opts = [])
    {
        if (!isset($opts['configuration'])) {
            $opts['configuration'] = $this->configuration;
        }

        if (!isset($opts['scope'])) {
            $opts['scope'] = 'openid';
        }

        if (!isset($opts['other_resource_scopes'])) {
            $opts['other_resource_scopes'] = [];
        }

        if (!isset($opts['access_token'])) {
            $opts['access_token'] = $this->getMockAccessToken();
        }

        $oAuthCredential = new AzureAdOAuthCredential(
            $opts['configuration'], $opts['access_token'], $opts['scope'], $opts['other_resource_scopes']);

        return $oAuthCredential;
    }
}