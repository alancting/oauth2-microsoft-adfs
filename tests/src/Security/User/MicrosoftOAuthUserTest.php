<?php

namespace Alancting\OAuth2\OpenId\Client\Test\Security\User;

use Alancting\OAuth2\OpenId\Client\Security\User\MicrosoftOAuthUser;
use Alancting\OAuth2\OpenId\Client\Test\Base\AbstractGeneralTestCase;

class MicrosoftOAuthUserTest extends AbstractGeneralTestCase
{
    public function testUser()
    {
        $mockUserName = 'mock-username';
        $mockRoles = ['mock-role1', 'mock-role2'];

        $oAuthUser = new MicrosoftOAuthUser($mockUserName, $mockRoles);

        $this->assertOAuthUser([
            'username' => $mockUserName,
            'roles' => $mockRoles,
        ], $oAuthUser);
    }
}