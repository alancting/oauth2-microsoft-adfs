<?php

namespace Alancting\OAuth2\OpenId\Client\Security\User;

use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class MicrosoftOAuthUserProvider implements UserProviderInterface
{
    private $_roles;

    public function __construct(array $roles = ['ROLE_USER', 'ROLE_OAUTH_USER'])
    {
        $this->_roles = $roles;
    }

    public function loadUserByUsername($username): UserInterface
    {
        return new MicrosoftOAuthUser($username, $this->_roles);
    }

    public function refreshUser(UserInterface $user): UserInterface
    {
        if (!$user instanceof MicrosoftOAuthUser) {
            throw new UnsupportedUserException(sprintf('Instances of "%s" are not supported.', \get_class($user)));
        }

        return $this->loadUserByUsername($user->getUsername());
    }

    public function supportsClass($class): bool
    {
        return MicrosoftOAuthUser::class === $class;
    }
}