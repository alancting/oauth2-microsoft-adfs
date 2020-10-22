<?php

namespace Alancting\OAuth2\Client\Security\User;

use Alancting\OAuth2\Client\Security\User\MicrosoftOAuthUser;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class MicrosoftOAuthUserProvider implements UserProviderInterface
{
    private $roles;

    public function __construct(array $roles = ['ROLE_USER', 'ROLE_OAUTH_USER'])
    {
        $this->roles = $roles;
    }

    public function loadUserByUsername($username): UserInterface
    {
        return new MicrosoftOAuthUser($username, $this->roles);
    }

    public function refreshUser(UserInterface $user): UserInterface
    {
        if (!$user instanceof MicrosoftOAuthUser) {
            throw new UnsupportedUserException(sprintf('Instances of "%s" are not supported.', \get_class($user)));
        }
        $user = $this->loadUserByUsername($user->getUsername());
        return $user;
    }

    public function supportsClass($class): bool
    {
        return MicrosoftOAuthUser::class === $class;
    }
}
