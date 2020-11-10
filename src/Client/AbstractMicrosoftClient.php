<?php

namespace Alancting\OAuth2\OpenId\Client\Client;

use League\OAuth2\Client\Provider\AbstractProvider;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Security\Core\Security;

abstract class AbstractMicrosoftClient extends AbstractMicrosoftKnpUClient
{
    private $_security;

    public function __construct(AbstractProvider $provider, RequestStack $requestStack, Security $security = null)
    {
        parent::__construct($provider, $requestStack);
        $this->_security = $security;
    }

    public function getLogoutUrl()
    {
        $idToken = '';
        $credential = $this->getOAuthCredential();
        if ($credential) {
            $idToken = $credential->getIdTokenJWT()->getJWT();
        }

        return $this->getOAuth2Provider()->getLogoutUrl($idToken);
    }

    public function getOAuthCredential()
    {
        return $this->getOAuthCredentialBySecurity($this->_security);
    }
}