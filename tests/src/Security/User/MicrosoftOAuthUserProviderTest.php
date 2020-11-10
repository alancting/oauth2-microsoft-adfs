<?php

namespace Alancting\OAuth2\OpenId\Client\Test\Security\User;

use Alancting\OAuth2\OpenId\Client\Security\User\MicrosoftOAuthUser;
use Alancting\OAuth2\OpenId\Client\Security\User\MicrosoftOAuthUserProvider;
use Alancting\OAuth2\OpenId\Client\Test\Base\AbstractGeneralTestCase;

class MicrosoftOAuthUserProviderTest extends AbstractGeneralTestCase
{
    const DEFAULT_ROLES = ['ROLE_USER', 'ROLE_OAUTH_USER'];

    protected $oAuthUserProvider;
    protected $mockUsername = 'mock-username';
    protected $mockRoles = ['mock-role1', 'mock-role2'];

    protected function setUp(): void
    {
        parent::setUp();
        $this->oAuthUserProvider = new MicrosoftOAuthUserProvider();
    }

    public function testLoadUserByUsername()
    {
        $oAuthUser = $this->oAuthUserProvider->loadUserByUsername($this->mockUsername);

        $this->assertOAuthUser([
            'username' => $this->mockUsername,
            'roles' => self::DEFAULT_ROLES,
        ], $oAuthUser);
    }

    public function testLoadUserByUsernameWithSpecificRoles()
    {
        $this->oAuthUserProvider = new MicrosoftOAuthUserProvider($this->mockRoles);
        $oAuthUser = $this->oAuthUserProvider->loadUserByUsername($this->mockUsername);

        $this->assertOAuthUser([
            'username' => $this->mockUsername,
            'roles' => $this->mockRoles,
        ], $oAuthUser);
    }

    public function testRefreshUserException()
    {
        $this->setExpectedException('Symfony\Component\Security\Core\Exception\UnsupportedUserException');

        $user = $this->prophesize('Symfony\Component\Security\Core\User\UserInterface');
        $this->oAuthUserProvider->refreshUser($user->reveal());
    }

    public function testRefreshUser()
    {
        $oAuthUser = $this->oAuthUserProvider->loadUserByUsername($this->mockUsername);
        $this->assertOAuthUser([
            'username' => $this->mockUsername,
            'roles' => self::DEFAULT_ROLES,
        ], $oAuthUser);

        $newMockUsername = 'new-mock-user-name';
        $newUser = new MicrosoftOAuthUser($newMockUsername, $this->mockRoles);
        $oAuthUser = $this->oAuthUserProvider->refreshUser($newUser);
        $this->assertOAuthUser([
            'username' => $newMockUsername,
            'roles' => self::DEFAULT_ROLES,
        ], $oAuthUser);
    }

    public function testSupportClass()
    {
        $support = $this->oAuthUserProvider->supportsClass('Alancting\OAuth2\OpenId\Client\Security\User\MicrosoftOAuthUser');
        $this->assertTrue($support);
    }

    public function testNotSupportClass()
    {
        $support = $this->oAuthUserProvider->supportsClass('Alancting\OAuth2\OpenId\Client\Security\User\MicrosoftOAuthUserProvider');
        $this->assertFalse($support);
    }
}