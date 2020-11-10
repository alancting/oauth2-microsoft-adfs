<?php

namespace Alancting\OAuth2\OpenId\Client\Security\Authenticator;

use KnpU\OAuth2ClientBundle\Security\Authenticator\SocialAuthenticator;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Security;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\Security\Core\User\UserInterface;

abstract class AbstractMicrosoftAuthenticator extends SocialAuthenticator
{
    abstract protected function getOAuthCredentialClass();

    private $clientRegistry;
    private $router;
    private $security;

    private $oAuthCredential;

    public function __construct(
        ClientRegistry $clientRegistry,
        RouterInterface $router,
        Security $security
    ) {
        $this->clientRegistry = $clientRegistry;
        $this->router = $router;
        $this->security = $security;
    }

    public function supports(Request $request)
    {
        if ($request->attributes->get('_route') === $this->_getLogoutRouteName()) {
            return false;
        }

        // Handle any request when credentials exists (credentials checking will be handle later)
        $oAuthCredential = $this->_getMicrosoftClient()->getOAuthCredentialBySecurity($this->security);
        if ($oAuthCredential) {
            $this->oAuthCredential = $oAuthCredential;

            return true;
        }

        // Handle when connect path
        if ($request->attributes->get('_route') === $this->_getConnectRouteName()) {
            return true;
        }

        return false;
    }

    public function getCredentials(Request $request)
    {
        $state = $request->query->get('state');
        $code = $request->query->get('code');

        // When state and code is returned, we assumed it's called from Adfs / Azure Ad
        if ((isset($state) && isset($code))) {
            $accessToken = $this->fetchAccessToken(
                $this->_getMicrosoftClient(),
                [
                    'state' => $state,
                    'scope' => $this->_getMicrosoftClientProvider()->getScopes(),
                ]
            );
            if (empty($this->oAuthCredential)) {
                $this->oAuthCredential = $this->_getMicrosoftOAuthCredential(
                    $accessToken,
                    $this->_getMicrosoftClientProvider()->getScopes(),
                    $this->_getMicrosoftClientProvider()->getOtherResourceScopes()
                );

                if ($this->oAuthCredential->isRefreshTokenUsable()) {
                    $pendingScoptToken = $this->_getMicrosoftClient()->fetchPendingOtherResourceAccessTokensByRefreshTokenByCredential($this->oAuthCredential);
                    $this->oAuthCredential->setOtherResourceOAuthCredentialsByTokens($pendingScoptToken);
                }
            } else {
                $otherResourceCredentials = $this->oAuthCredential->getOtherResourceCredentials();

                $targetScope = false;
                if (isset(($accessToken->getValues())['scope'])) {
                    $targetScope = ($accessToken->getValues())['scope'];
                }

                if (count($otherResourceCredentials) && $targetScope
                    && array_key_exists($targetScope, $otherResourceCredentials)
                ) {
                    $this->oAuthCredential->setOtherResourceOAuthCredential(
                        $targetScope,
                        $this->_getMicrosoftOAuthCredential($accessToken, $targetScope)
                    );
                } else {
                    $this->oAuthCredential->update(
                        $this->_getMicrosoftClient()->getMicrosoftConfiguration(),
                        $accessToken
                    );
                }
            }
        } else {
            if (!empty($this->oAuthCredential) && $this->oAuthCredential->isRefreshTokenUsable()) {
                if ($this->oAuthCredential->isExpired()) {
                    $accessToken = $this->_getMicrosoftClient()->fetchAccessTokenByRefreshToken($this->oAuthCredential->getRefreshToken());
                    $this->oAuthCredential->update($this->_getMicrosoftClient()->getMicrosoftConfiguration(), $accessToken);
                }

                $pendingScoptToken = $this->_getMicrosoftClient()->fetchPendingOtherResourceAccessTokensByRefreshTokenByCredential($this->oAuthCredential);
                $this->oAuthCredential->setOtherResourceOAuthCredentialsByTokens($pendingScoptToken);
            }
        }

        return $this->oAuthCredential;
    }

    public function checkCredentials($credential, UserInterface $user): bool
    {
        if ($credential->isExpired()
            && !$credential->isRefreshTokenUsable()
        ) {
            return false;
        }

        return true;
    }

    public function getUser($credential, UserProviderInterface $userProvider)
    {
        $key = $this->_getMicrosoftClientProvider()->getUserKey();
        $username = $credential->getIdTokenJWT()->get($key);

        return $userProvider->loadUserByUsername($username);
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
    {
        $token->setAttribute($this->_getMicrosoftClient()->getClientKey(), $this->oAuthCredential);

        $pendingScopes =  $this->oAuthCredential->getPendingOtherResourceCredentialScopes();

        if (count($pendingScopes)) {
            return $this->_getMicrosoftClient()->startAuthorization(
                $request,
                [$pendingScopes[0]]
            );
        }

        if ($this->_shouldStartValidate($request)) {
            $state = $request->query->get('state');
            if (!empty($state)) {
                return new RedirectResponse($state);
            }

            return null;
        }

        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        return $this->start($request, $exception);
    }

    public function start(Request $request, AuthenticationException $authException = null)
    {
        if ($this->_shouldStartValidate($request)) {
            return $this->_getMicrosoftClient()->startAuthorization($request);
        }
    }

    private function _getMicrosoftOAuthCredential($accessToken, $scope, $otherResourceScopes = [])
    {
        $className = $this->getOAuthCredentialClass();

        return new $className($this->_getMicrosoftClient()->getMicrosoftConfiguration(), $accessToken, $scope, $otherResourceScopes);
    }

    private function _getMicrosoftClient()
    {
        return $this->clientRegistry->getClient('microsoft_openid');
    }

    private function _getMicrosoftClientProvider()
    {
        return $this->_getMicrosoftClient()->getOAuth2Provider();
    }

    private function _shouldStartValidate(Request $request)
    {
        $isConnectPath = ($request->attributes->get('_route') === $this->_getConnectRouteName());
        $isSecuirtyExists = (
            $this->security->getToken() !== null &&
            $this->security->getUser() !== null);
        $isCredentialRequireAndCannotRefresh = (
            $this->oAuthCredential !== null &&
            $this->oAuthCredential->isExpired() &&
            !$this->oAuthCredential->isRefreshTokenUsable());

        return (
            $isConnectPath ||
            !$isSecuirtyExists ||
            $isCredentialRequireAndCannotRefresh
        );
    }

    private function _getConnectRouteName()
    {
        return 'microsoft_openid_connect';
    }

    private function _getLogoutRouteName()
    {
        return 'microsoft_openid_logout';
    }
}