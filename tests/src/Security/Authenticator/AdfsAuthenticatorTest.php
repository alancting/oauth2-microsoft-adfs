<?php

namespace Alancting\OAuth2\OpenId\Client\Test\Security\Authenticator;

use Mockery as m;

use Alancting\OAuth2\OpenId\Client\Security\Authenticator\AdfsAuthenticator;
use Alancting\OAuth2\OpenId\Client\Security\User\MicrosoftOAuthUserProvider;
use Symfony\Component\HttpFoundation\Request;
use Alancting\OAuth2\OpenId\Client\Test\Base\AbstractAdfsTestCase;

class AdfsAuthenticatorTest extends AbstractAdfsTestCase
{
    protected $router;
    protected $security;

    protected $configuration;
    protected $authenticator;
    protected $request;

    protected $mockClient;

    protected function setUp(): void
    {
        parent::setUp();

        $this->router = $this->prophesize('Symfony\Component\Routing\RouterInterface');
        $this->security = $this->prophesize('Symfony\Component\Security\Core\Security');
    }

    public function testSupportsNotSupportLogoutRoute()
    {
        $mocks = [
            'mock_oauth_credential' => m::mock('Alancting\OAuth2\OpenId\Client\Security\Credential\AdfsOAuthCredential'),
        ];
        $this->authenticator = $this->getSimpleAuthenticator($mocks);
        $supports = $this->authenticator->supports($this->_getLogoutPathRequest());

        $this->assertFalse($supports);
    }

    public function testSupportsOauthCredentiaNotlFoundNotConnectRoute()
    {
        $this->authenticator = $this->getSimpleAuthenticator();
        $supports = $this->authenticator->supports($this->_getAnyPathRequest());

        $this->assertFalse($supports);
    }

    public function testSupportsOauthCredentiaFound()
    {
        $mocks = [
            'mock_oauth_credential' => m::mock('Alancting\OAuth2\OpenId\Client\Security\Credential\AdfsOAuthCredential'),
        ];
        $this->authenticator = $this->getSimpleAuthenticator($mocks);
        $supports = $this->authenticator->supports($this->_getAnyPathRequest());

        $this->assertTrue($supports);
    }

    public function testSupportsSupportConnectRoute()
    {
        $this->authenticator = $this->getSimpleAuthenticator();

        $request = new Request([], [], ['_route' => 'microsoft_openid_connect']);
        $supports = $this->authenticator->supports($request);

        $this->assertTrue($supports);
    }

    public function testGetCredentialsNoRefreshTokenFromCallback()
    {
        $mocks = [
            'other_resources' => [
                'other_resource_credential_1',
                'other_resource_credential_2',
            ],
        ];
        $this->authenticator = $this->getSimpleAuthenticator($mocks);
        $checkCredential = $this->authenticator->getCredentials($this->_getAnyPathRequest(true));

        $expectedCredential = $this->getDefaultExpectedCredential();
        $expectedCredential['num_other_resources'] = 2;
        $expectedCredential['num_pending_other_resources'] = 2;

        $this->assertOAuthCredential($expectedCredential, $checkCredential);
    }

    public function testGetCredentialsNoRefreshTokenFromCallbackUpdateMain()
    {
        $mocks = [
            'other_resources' => [
                'other_resource_credential_1',
                'other_resource_credential_2',
            ],
            'mock_access_tokens' => [
                $this->getMockAccessToken(),
                $this->getMockAccessToken(['mock_token' => 'mock-access-token-new']),
            ],
        ];
        $this->authenticator = $this->getSimpleAuthenticator($mocks);
        $this->authenticator->getCredentials($this->_getAnyPathRequest(true));

        $secondRequest = new Request([
            'state' => 'mock-state', 'code' => 'mock-code', ], [], []);
        $checkCredential = $this->authenticator->getCredentials($this->_getAnyPathRequest(true));

        $expectedCredential = $this->getDefaultExpectedCredential();
        $expectedCredential['access_token'] ='mock-access-token-new';
        $expectedCredential['num_other_resources'] = 2;
        $expectedCredential['num_pending_other_resources'] = 2;

        $this->assertOAuthCredential($expectedCredential, $checkCredential);
    }

    public function testGetCredentialsNoRefreshTokenFromCallbackOtherResource()
    {
        $mocks = [
            'other_resources' => [
                'other_resource_credential_1',
                'other_resource_credential_2',
            ],
            'mock_access_tokens' => [
                $this->getMockAccessToken(),
                $this->getMockAccessToken([
                    'scope' => 'other_resource_credential_1',
                    'mock_token' => 'mock-access-token-other_resource_credential_1',
                ]),
            ],
        ];
        $this->authenticator = $this->getSimpleAuthenticator($mocks);
        $this->authenticator->getCredentials($this->_getAnyPathRequest(true));
        $checkCredential = $this->authenticator->getCredentials($this->_getAnyPathRequest(true));

        $expectedMainCredential = $this->getDefaultExpectedCredential();
        $expectedMainCredential['num_other_resources'] = 2;
        $expectedMainCredential['num_pending_other_resources'] = 1;

        $expectedCredentialCredential = $this->getDefaultExpectedCredential();
        $expectedCredentialCredential['scope'] = 'other_resource_credential_1';
        $expectedCredentialCredential['access_token'] ='mock-access-token-other_resource_credential_1';

        $this->assertOAuthCredential($expectedMainCredential, $checkCredential);
        $this->assertOAuthCredential($expectedCredentialCredential, $checkCredential->getOtherResourceCredential('other_resource_credential_1'));
    }

    public function testGetCredentialsHvRefreshTokenFromCallback()
    {
        $mocks = [
            'other_resources' => [
                'other_resource_credential_1',
                'other_resource_credential_2',
            ],
            'mock_access_tokens' => [
                $this->getMockAccessToken([
                    'mock_refresh_token' => 'mock-refresh-token',
                ]),
            ],
            'mock_other_resources_access_tokens' => [
                'other_resource_credential_1' => $this->getMockAccessToken(),
                'other_resource_credential_2' => $this->getMockAccessToken(),
            ],
        ];
        $this->authenticator = $this->getSimpleAuthenticator($mocks);
        $checkCredential = $this->authenticator->getCredentials($this->_getAnyPathRequest(true));

        $expectedMainCredential = $this->getDefaultExpectedCredential();
        $expectedMainCredential['num_other_resources'] = 2;
        $expectedMainCredential['num_pending_other_resources'] = 0;
        $expectedMainCredential['refresh_token'] = [
            'token' => 'mock-refresh-token',
            'is_expired' => false,
        ];

        $this->assertOAuthCredential($expectedMainCredential, $checkCredential);
    }

    public function testGetCredentialsNoRefreshTokenNotFromCallback()
    {
        $mocks = [
            'other_resources' => [
                'other_resource_credential_1',
                'other_resource_credential_2',
            ],
            'mock_access_tokens' => [
                $this->getMockAccessToken(),

            ],
            'mock_other_resources_access_tokens' => [
                'other_resource_credential_1' => $this->getMockAccessToken(),
                'other_resource_credential_2' => $this->getMockAccessToken(),
            ],
        ];
        $this->authenticator = $this->getSimpleAuthenticator($mocks);
        $checkCredential = $this->authenticator->getCredentials($this->_getAnyPathRequest());

        $this->assertEquals(null, $checkCredential);
    }

    public function testGetCredentialshHvRefreshTokenNotFromCallback()
    {
        $mocks = [
            'other_resources' => [
                'other_resource_credential_1',
                'other_resource_credential_2',
            ],
            'mock_access_tokens' => [
                $this->getMockAccessToken([
                    'mock_expires' => 0,
                    'mock_refresh_token' => 'mock-refresh-token',
                ]),
            ],
            'mock_other_resources_access_tokens' => [
                'other_resource_credential_1' => $this->getMockAccessToken(),
                'other_resource_credential_2' => $this->getMockAccessToken(),
            ],
        ];
        $this->authenticator = $this->getSimpleAuthenticator($mocks);
        $this->authenticator->getCredentials($this->_getAnyPathRequest(true));
        $checkCredential = $this->authenticator->getCredentials($this->_getAnyPathRequest());

        $expectedMainCredential = $this->getDefaultExpectedCredential();
        $expectedMainCredential['num_other_resources'] = 2;
        $expectedMainCredential['num_pending_other_resources'] = 0;
        $expectedMainCredential['refresh_token'] = [
            'token' => 'mock-refresh-token',
            'is_expired' => false,
        ];

        $this->assertOAuthCredential($expectedMainCredential, $checkCredential);
    }

    public function testCheckCredentialsExpiredAndValidRefreshToken()
    {
        $mockCredential = $this->getMockCredential([
            'mock_is_expired' => true,
            'mock_is_refresh_token_usable' => true,
        ]);
        $mockUser = $this->getMockUser();

        $this->authenticator = $this->getSimpleAuthenticator([
            'mock_oauth_credential' => $mockCredential,
        ]);

        $result = $this->authenticator->checkCredentials($mockCredential, $mockUser);
        $this->assertTrue($result);
    }

    public function testCheckCredentialsExpiredAndInvalidRefreshToken()
    {
        $mockCredential = $this->getMockCredential([
            'mock_is_expired' => true,
            'mock_is_refresh_token_usable' => false,
        ]);
        $mockUser = $this->getMockUser();

        $this->authenticator = $this->getSimpleAuthenticator([
            'mock_oauth_credential' => $mockCredential,
        ]);

        $result = $this->authenticator->checkCredentials($mockCredential, $mockUser);
        $this->assertFalse($result);
    }

    public function testCheckCredentialsNotExpiredAndValidRefreshToken()
    {
        $mockCredential = $this->getMockCredential([
            'mock_is_expired' => false,
            'mock_is_refresh_token_usable' => true,
        ]);
        $mockUser = $this->getMockUser();

        $this->authenticator = $this->getSimpleAuthenticator([
            'mock_oauth_credential' => $mockCredential,
        ]);

        $result = $this->authenticator->checkCredentials($mockCredential, $mockUser);
        $this->assertTrue($result);
    }

    public function testCheckCredentialsNotExpiredAndInvalidRefreshToken()
    {
        $mockCredential = $this->getMockCredential([
            'mock_is_expired' => false,
            'mock_is_refresh_token_usable' => false,
        ]);
        $mockUser = $this->getMockUser();

        $this->authenticator = $this->getSimpleAuthenticator([
            'mock_oauth_credential' => $mockCredential,
        ]);

        $result = $this->authenticator->checkCredentials($mockCredential, $mockUser);
        $this->assertTrue($result);
    }

    public function testGetUser()
    {
        $mockCredential = $this->getMockCredential([
            'mock_is_expired' => false,
            'mock_is_refresh_token_usable' => false,
        ]);
        $userProvider  = new MicrosoftOAuthUserProvider();

        $this->authenticator = $this->getSimpleAuthenticator([
            'mock_oauth_credential' => $mockCredential,
        ]);

        $checkOAuthUser = $this->authenticator->getUser($mockCredential, $userProvider);
        $this->assertOAuthUser(
            [
                'username' => 'mock-user-name-from-id-token',
                'roles' => ['ROLE_USER', 'ROLE_OAUTH_USER'],
            ], $checkOAuthUser);
    }

    public function testOnAuthenticationSuccessWithAuthWithOtherResource()
    {
        $token = $this->prophesize('Symfony\Component\Security\Core\Authentication\Token\TokenInterface');

        $mocks = [
            'other_resources' => [
                'other_resource_credential_1',
                'other_resource_credential_2',
            ],
        ];
        $request = $this->_getAnyPathRequest(true);
        $this->authenticator = $this->getSimpleAuthenticator($mocks);
        $this->authenticator->getCredentials($request);
        $checkResponse = $this->authenticator->onAuthenticationSuccess($request, $token->reveal(), 'provider-key');

        $this->assertInstanceOf('Symfony\Component\HttpFoundation\RedirectResponse', $checkResponse);
    }

    public function testOnAuthenticationSuccessWithAuthWithNoOtherResource()
    {
        $token = $this->prophesize('Symfony\Component\Security\Core\Authentication\Token\TokenInterface');

        $request = $this->_getAnyPathRequest(true);
        $this->authenticator = $this->getSimpleAuthenticator();
        $this->authenticator->getCredentials($request);
        $checkResponse = $this->authenticator->onAuthenticationSuccess($request, $token->reveal(), 'provider-key');

        $this->assertInstanceOf('Symfony\Component\HttpFoundation\RedirectResponse', $checkResponse);
        $this->assertEquals('mock-state', $checkResponse->getTargetUrl());
    }

    public function testOnAuthenticationSuccessOutOfAuth()
    {
        $token = $this->prophesize('Symfony\Component\Security\Core\Authentication\Token\TokenInterface');

        $mocks = [
            'other_resources' => [
                'other_resource_credential_1',
                'other_resource_credential_2',
            ],
        ];
        $request = $this->_getAnyPathRequest(true);
        $this->authenticator = $this->getSimpleAuthenticator();
        $this->authenticator->getCredentials($request);

        $nextRequest = $this->_getAnyPathRequest();
        $checkResponse = $this->authenticator->onAuthenticationSuccess($nextRequest, $token->reveal(), 'provider-key');

        $this->assertEquals(null, $checkResponse);
    }

    public function testStart()
    {
        m::close();
        $checkedResponse = $this->_getResponseForStartTests([
            'is_connect_path' => false,
            'secuirty_token_exists' => false,
            'secuirty_user_exists' => false,
        ]);
        $this->assertInstanceOf('Symfony\Component\HttpFoundation\RedirectResponse', $checkedResponse);

        m::close();
        $checkedResponse = $this->_getResponseForStartTests([
            'is_connect_path' => true,
            'secuirty_token_exists' => true,
            'secuirty_user_exists' => true,
            'credential_is_expired' => false,
            'credential_refresh_token_usable' => true,
        ]);
        $this->assertInstanceOf('Symfony\Component\HttpFoundation\RedirectResponse', $checkedResponse);

        m::close();
        $checkedResponse = $this->_getResponseForStartTests([
            'is_connect_path' => false,
            'secuirty_token_exists' => false,
            'secuirty_user_exists' => false,
            'credential_is_expired' => false,
            'credential_refresh_token_usable' => true,
        ]);
        $this->assertInstanceOf('Symfony\Component\HttpFoundation\RedirectResponse', $checkedResponse);

        m::close();
        $checkedResponse = $this->_getResponseForStartTests([
            'is_connect_path' => false,
            'secuirty_token_exists' => false,
            'secuirty_user_exists' => true,
            'credential_is_expired' => false,
            'credential_refresh_token_usable' => true,
        ]);
        $this->assertInstanceOf('Symfony\Component\HttpFoundation\RedirectResponse', $checkedResponse);

        m::close();
        $checkedResponse = $this->_getResponseForStartTests([
            'is_connect_path' => false,
            'secuirty_token_exists' => true,
            'secuirty_user_exists' => false,
            'credential_is_expired' => false,
            'credential_refresh_token_usable' => true,
        ]);
        $this->assertInstanceOf('Symfony\Component\HttpFoundation\RedirectResponse', $checkedResponse);

        m::close();
        $checkedResponse = $this->_getResponseForStartTests([
            'is_connect_path' => false,
            'secuirty_token_exists' => true,
            'secuirty_user_exists' => false,
            'credential_is_expired' => true,
            'credential_refresh_token_usable' => false,
        ]);
        $this->assertInstanceOf('Symfony\Component\HttpFoundation\RedirectResponse', $checkedResponse);

        m::close();
        $checkedResponse = $this->_getResponseForStartTests([
            'is_connect_path' => false,
            'secuirty_token_exists' => true,
            'secuirty_user_exists' => true,
            'credential_is_expired' => true,
            'credential_refresh_token_usable' => false,
        ]);
        $this->assertInstanceOf('Symfony\Component\HttpFoundation\RedirectResponse', $checkedResponse);
    }

    public function testNotStart()
    {
        m::close();
        $checkedResponse = $this->_getResponseForStartTests([
            'is_connect_path' => false,
            'secuirty_token_exists' => true,
            'secuirty_user_exists' => true,
            'credential_is_expired' => false,
            'credential_refresh_token_usable' => true,
        ]);
        $this->assertEquals(null, $checkedResponse);

        m::close();
        $checkedResponse = $this->_getResponseForStartTests([
            'is_connect_path' => false,
            'secuirty_token_exists' => true,
            'secuirty_user_exists' => true,
            'credential_is_expired' => true,
            'credential_refresh_token_usable' => true,
        ]);
        $this->assertEquals(null, $checkedResponse);
    }

    private function getSimpleAuthenticator($mocks = [])
    {
        if (!isset($mocks['mock_oauth_credential'])) {
            $mocks['mock_oauth_credential'] = null;
        }

        if (!isset($mocks['other_resources'])) {
            $mocks['other_resources'] = [];
        }

        if (!isset($mocks['mock_access_tokens'])) {
            $mocks['mock_access_tokens'] = [];
        }

        if (!isset($mocks['mock_other_resources_access_tokens'])) {
            $mocks['mock_other_resources_access_tokens'] = [];
        }

        $mockProvider = $this->getMockProvider($mocks['other_resources']);
        $this->mockClient = $this->getMockClient(
            $mocks['mock_oauth_credential'],
            $mockProvider,
            $mocks['mock_access_tokens'],
            $mocks['mock_other_resources_access_tokens']);

        return new AdfsAuthenticator(
            $this->getMockClientRegistry($this->mockClient),
            $this->router->reveal(),
            $this->security->reveal()
        );
    }

    private function getMockClientRegistry($mockClient)
    {
        $mockClientRegistry = m::mock('KnpU\OAuth2ClientBundle\Client\ClientRegistry');
        $mockClientRegistry->shouldReceive('getClient')->andReturn($mockClient);

        return $mockClientRegistry;
    }

    private function getMockUser($mocks = [])
    {
        $mockUser = m::mock('Alancting\OAuth2\OpenId\Client\Security\User\MicrosoftOAuthUser');
        if (isset($mocks['mock_username'])) {
            $mockUser
                ->shouldReceive('getUsername')
                ->andReturn($mocks['mock_username']);
        }

        return $mockUser;
    }

    private function _getLogoutPathRequest()
    {
        return new Request([], [], ['_route' => 'microsoft_openid_logout']);
    }

    private function _getConnectPathRequest($isCallback = false)
    {
        $params = [];
        if ($isCallback) {
            $params = ['state' => 'mock-state', 'code' => 'mock-code'];
        }

        return new Request($params, [], ['_route' => 'microsoft_openid_connect']);
    }

    private function _getAnyPathRequest($isCallback = false)
    {
        $params = [];
        if ($isCallback) {
            $params = ['state' => 'mock-state', 'code' => 'mock-code'];
        }

        return new Request($params, [], ['_route' => 'any']);
    }

    private function _getResponseForStartTests($opts = [])
    {
        $request = $this->_getAnyPathRequest();
        $securityToken = null;
        $securityUser = null;
        $mockCredential = null;

        if (isset($opts['is_connect_path']) && $opts['is_connect_path']) {
            $request = $this->_getConnectPathRequest();
        }

        if (isset($opts['secuirty_token_exists']) && $opts['secuirty_token_exists']) {
            $securityToken = $this->prophesize('Symfony\Component\Security\Core\Authentication\Token\TokenInterface');
        }

        if (isset($opts['secuirty_user_exists']) && $opts['secuirty_user_exists']) {
            $securityUser = $this->prophesize('Symfony\Component\Security\Core\User\UserInterface');
        }

        if (isset($opts['credential_is_expired']) || isset($opts['credential_refresh_token_usable'])) {
            $mockCredential = $this->getMockCredential([
                'mock_is_expired' => isset($opts['credential_is_expired']) ? $opts['credential_is_expired'] : false,
                'mock_is_refresh_token_usable' => isset($opts['credential_refresh_token_usable']) ? $opts['credential_refresh_token_usable'] : false,
            ]);
        }

        $this->security->getToken()->willReturn($securityToken);
        $this->security->getUser()->willReturn($securityUser);

        if (!empty($mockCredential)) {
            $this->authenticator = $this->getSimpleAuthenticator([
                'mock_oauth_credential' => $mockCredential,
            ]);
        } else {
            $this->authenticator = $this->getSimpleAuthenticator();
        }

        $this->authenticator->supports($request);

        return $this->authenticator->start($request);
    }
}