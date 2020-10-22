<?php

namespace Alancting\OAuth2\Client\Security\User;

use Symfony\Component\Security\Core\User\UserInterface;

class MicrosoftOAuthUser implements UserInterface
{
    private $username;
    private $roles;

    public function __construct($username, array $roles)
    {
        $this->username = $username;
        $this->roles = $roles;
    }

    public function getRoles()
    {
        return $this->roles;
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
        return $this->username;
    }

    public function eraseCredentials()
    {
        // Do nothing.
    }
}