<?php

namespace Alancting\OAuth2\Client\Client;

use KnpU\OAuth2ClientBundle\Client\OAuth2Client;

use League\OAuth2\Client\Token\AccessToken;
use Alancting\OAuth2\Client\Provider\Adfs\AdfsResourceOwner;
use League\OAuth2\Client\Provider\AbstractProvider;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Security\Core\Security;

class AbstractMicrosoftClient extends OAuth2Client
{
    private $security;
    
    public function __construct(AbstractProvider $provider, RequestStack $requestStack, Security $security)
    {
        parent::__construct($provider, $requestStack);
        $this->security = $security;
    }
    
    /**
     * @return AdfsResourceOwner|\League\OAuth2\Client\Provider\ResourceOwnerInterface
     */
    public function fetchUserFromToken(AccessToken $accessToken)
    {
        return parent::fetchUserFromToken($accessToken);
    }

    /**
     * @return AdfsResourceOwner|\League\OAuth2\Client\Provider\ResourceOwnerInterface
     */
    public function fetchUser()
    {
        return parent::fetchUser();
    }

    /**
     * @return AdfsResourceOwner|\League\OAuth2\Client\Provider\ResourceOwnerInterface
     */
    public function fetchAccessTokenByRefreshToken(string $refreshToken, array $options = [])
    {
        $params = [
            'refresh_token' => $refreshToken
        ];
        
        return $this->getOAuth2Provider()->getAccessToken(
            'refresh_token',
            array_merge($params, $options)
        );
    }

    protected function getSecurity()
    {
        return $this->security;
    }
}