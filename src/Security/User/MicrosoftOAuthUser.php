<?php

namespace Alancting\OAuth2\OpenId\Client\Security\User;

use Symfony\Component\Security\Core\User\UserInterface;

class MicrosoftOAuthUser implements UserInterface
{
    private $_username;
    private $_roles;

    public function __construct($username, array $roles)
    {
        $this->_username = $username;
        $this->_roles = $roles;
    }

    public function getRoles()
    {
        return $this->_roles;
    }

    public function getPassword(): ?string
    {
        return '';
    }

    public function getSalt(): ?string
    {
        return null;
    }

    public function getUsername(): string
    {
        return $this->_username;
    }

    public function eraseCredentials()
    {
        // Do nothing.
    }
}