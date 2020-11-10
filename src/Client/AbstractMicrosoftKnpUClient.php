<?php

namespace Alancting\OAuth2\OpenId\Client\Client;

use KnpU\OAuth2ClientBundle\Client\OAuth2Client;

use League\OAuth2\Client\Provider\AbstractProvider;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Request;
use Alancting\OAuth2\OpenId\Client\Security\Token\MicrosoftRefreshToken;
use Alancting\OAuth2\OpenId\Client\Security\Credential\MicrosoftOAuthCredential;
use Symfony\Component\Security\Core\Security;

abstract class AbstractMicrosoftKnpUClient extends OAuth2Client
{
    abstract public function getClientKey();

    public function __construct(AbstractProvider $provider, RequestStack $requestStack)
    {
        parent::__construct($provider, $requestStack);
    }

    public function startAuthorization(
        Request $request,
        array $scopes = []
    ) {
        $state = !empty($request->query->get('state')) ? $request->query->get('state') : $request->getPathInfo();
        if (empty($scopes)) {
            $scopes = $this->getOAuth2Provider()->getMicrosoftResourceScopes();
        }

        return $this->redirect(
            array_merge($this->getOAuth2Provider()->getDefaultScopes(), $scopes),
            ['state' => $state]
        );
    }

    public function fetchPendingOtherResourceAccessTokensByRefreshTokenByCredential(MicrosoftOAuthCredential $credential = null)
    {
        $tokens = [];
        if ($credential && !empty($credential->getRefreshToken())) {
            $pendingScopes = $credential->getPendingOtherResourceCredentialScopes();
            if (count($pendingScopes)) {
                foreach ($pendingScopes as $pendingScope) {
                    $tokens[$pendingScope] = $this->fetchAccessTokenByRefreshToken(
                        $credential->getRefreshToken(),
                        [$pendingScope]
                    );
                }
            }
        }

        return $tokens;
    }

    public function fetchAccessTokenByRefreshToken(
        MicrosoftRefreshToken $refreshToken,
        array $scopes = []
    ) {
        $params = [
            'refresh_token' => $refreshToken->getToken(),
            'scope' => array_merge($this->getOAuth2Provider()->getDefaultScopes(), $scopes),
        ];

        return $this->getOAuth2Provider()->getAccessToken(
            'refresh_token',
            $params
        );
    }

    public function getOAuthCredentialBySecurity(Security $security)
    {
        if ($security->getToken() !== null
            && $security->getUser() !== null
            && isset(($security->getToken()->getAttributes())[$this->getClientKey()])
        ) {
            return ($security->getToken()->getAttributes())[$this->getClientKey()];
        }

        return false;
    }

    public function getMicrosoftConfiguration()
    {
        return $this->getOAuth2Provider()->getMicrosoftConfiguration();
    }
}