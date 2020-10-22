<?php

namespace Alancting\OAuth2\Client\Security\Authenticator;

use KnpU\OAuth2ClientBundle\Security\Authenticator\SocialAuthenticator;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Security;
use Psr\Log\LoggerInterface;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\Security\Core\User\UserInterface;

use Alancting\OAuth2\Client\Security\Token\MicrosoftRefreshToken;
use Alancting\OAuth2\Client\Security\Token\MicrosoftAdfsOAuthCredential;
use Alancting\OAuth2\Client\Security\Credential\MicrosoftOAuthCredential;

use Alancting\Microsoft\JWT\AzureAd\AzureAdConfiguration as Configuration;
use Alancting\Microsoft\JWT\AzureAd\AzureAdAccessTokenJWT as AccessTokenJWT;
use Alancting\Microsoft\JWT\AzureAd\AzureAdIdTokenJWT as IdTokenJWT;

abstract class AbstractMicrosoftAuthenticator extends SocialAuthenticator
{
    abstract protected function getLogoutPath();
    abstract protected function getConnectPath();
  
    abstract protected function getClientName();
  
    abstract protected function getOAuthCredentialKey();
    
    abstract protected function getOAuthCredentialClass();
    
    private $clientRegistry;
    private $router;
    private $logger;
    private $security;

    private $oAuthCredential;

    public function __construct(
        ClientRegistry $clientRegistry,
        RouterInterface $router,
        Security $security,
        LoggerInterface $logger
    ) {
        $logger->debug(sprintf('*** [%s] %s ***', get_called_class(), __FUNCTION__));

        $this->clientRegistry = $clientRegistry;
        $this->router = $router;
        $this->logger = $logger;
        $this->security = $security;
    }
    
    public function supports(Request $request)
    {
        $this->logger->debug(sprintf('*** [%s] %s ***', get_called_class(), __FUNCTION__));

        if ($request->attributes->get('_route') === $this->getLogoutPath()) {
            return false;
        }
        
        if ($request->attributes->get('_route') === $this->getConnectPath()) {
            $this->_loadSecurityMicrosoftOAuthCredentialIfExists();
            return true;
        }
        
        if ($this->_securityMicrosoftOAuthCredentialExists()) {
            $this->_loadSecurityMicrosoftOAuthCredentialIfExists();
            // if ($this->oAuthCredential->isExpired()) {
            return true;
            // }
        }
        
        return false;
    }
    
    public function getCredentials(Request $request)
    {
        $this->logger->debug(sprintf('*** [%s] %s ***', get_called_class(), __FUNCTION__));
        
        $state = $request->query->get('state');
        $code = $request->query->get('code');
        
        if ((isset($state) && isset($code))) {
            $this->logger->debug(sprintf('*** [%s] %s: fetch from code with scope: %s ... ***', get_called_class(), __FUNCTION__, print_r($this->_getMicrosoftClientProvider()->getScopes(), 1)));
            
            $accessToken = $this->fetchAccessToken(
                $this->_getMicrosoftClient(),
                [
                  'state' => $state,
                  'scope' => $this->_getMicrosoftClientProvider()->getScopes(),
                ]
            );

            if (!$this->_securityExists()) {
                $this->logger->debug(sprintf('*** [%s] %s: set main token ***', get_called_class(), __FUNCTION__));
                $this->oAuthCredential = $this->_getMicrosoftOAuthCredential($accessToken, $this->_getMicrosoftClientProvider()->getOtherResourceScopes());
            } else {
                $otherResourceCredentials = $this->oAuthCredential->getOtherResourceCredentials();
                
                $targetScope = false;
                if (isset(($accessToken->getValues())['scope'])) {
                    $targetScope = ($accessToken->getValues())['scope'];
                }
                
                if (count($otherResourceCredentials) && $targetScope
                    && array_key_exists($targetScope, $otherResourceCredentials)
                ) {
                    $this->logger->debug(sprintf('*** [%s] %s: set sub %s token ***', get_called_class(), __FUNCTION__, $targetScope));
                    $this->oAuthCredential->setOtherResourceOAuthCredential(
                        $targetScope,
                        $this->_getMicrosoftOAuthCredential($accessToken)
                    );
                } else {
                    $this->logger->debug(sprintf('*** [%s] %s: update main token ***', get_called_class(), __FUNCTION__));
                    $this->oAuthCredential->update(
                        $this->_getMicrosoftConfiguration(),
                        $accessToken
                    );
                }
            }
        } else {
            if ($this->oAuthCredential->canRefreshToken()) {
                if ($this->oAuthCredential->isExpired()) {
                    $this->logger->debug(sprintf('*** [%s] %s: update expired main token (refresh token) ***', get_called_class(), __FUNCTION__));

                    $accessToken = $this->fetchAccessTokenByRefreshToken($this->oAuthCredential->getRefreshToken()->getToken());
                    $this->oAuthCredential->update($this->_getMicrosoftConfiguration(), $accessToken);
                }

                $expiredCredentialScopes = $this->oAuthCredential->getExpiredResourceCredentialScopes();
                if (count($expiredCredentialScopes)) {
                    foreach ($expiredCredentialScopes as $expiredCredentialScope) {
                        $this->logger->debug(sprintf('*** [%s] %s: set expired sub %s token (refresh token) ***', get_called_class(), __FUNCTION__, $expiredCredentialScope));
                      
                        $accessToken = $this->fetchAccessTokenByRefreshToken(
                            $this->oAuthCredential->getRefreshToken()->getToken(),
                            ['openid', $expiredCredentialScope]
                        );
                        $this->oAuthCredential->setOtherResourceOAuthCredential(
                            $expiredCredentialScope,
                            $this->_getMicrosoftOAuthCredential($accessToken)
                        );
                    }
                }
            }
        }
        return $this->oAuthCredential;
    }
    
    public function checkCredentials($credential, UserInterface $user): bool
    {
        $this->logger->debug(sprintf('*** [%s] %s ***', get_called_class(), __FUNCTION__));
        
        if ($credential->isExpired()
            && $credential->haveRefreshToken()
            && !$credential->canRefreshToken()
        ) {
            return false;
        }
        return true;
    }
    
    public function getUser($credential, UserProviderInterface $userProvider)
    {
        $this->logger->debug(sprintf('*** [%s] %s ***', get_called_class(), __FUNCTION__));
        
        
        $key = $this->_getMicrosoftClientProvider()->getUserKey();
        $username = $credential->getIdTokenJWT()->get($key);
        $this->logger->debug(
            sprintf('*** [%s] %s ***', get_called_class(), __FUNCTION__),
            ['key' => $key, 'username' => $username]
        );
        return $userProvider->loadUserByUsername($username);
    }
    
    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
    {
        $this->logger->debug(sprintf('*** [%s] %s ***', get_called_class(), __FUNCTION__));

        $token->setAttribute($this->getOAuthCredentialKey(), $this->oAuthCredential);
      
        $missingScopes = $this->oAuthCredential->getMissingOtherResourceCredentialScopes();
        $expiredCredentialScopes = $this->oAuthCredential->getExpiredResourceCredentialScopes();
        
        $this->logger->debug(
            sprintf('*** [%s] %s: missing %s, expired: %s scope(s) ***', get_called_class(), __FUNCTION__, count($missingScopes), count($expiredCredentialScopes))
        );
        
        if (count($missingScopes)+count($expiredCredentialScopes)) {
            return $this->redirectToAuthorization(
                $request,
                ['openid', (array_merge($missingScopes, $expiredCredentialScopes))[0]]
            );
        }
        
        if ($this->shouldStartValidate($request)) {
            $state = $request->query->get('state');
            // $redirectUri = !empty($state) ? $state : $request->getPathInfo();
            if (!empty($state)) {
                return new RedirectResponse($state);
            } else {
                return null;
            }
        } else {
            return null;
        }
    }
    
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        $this->logger->debug(sprintf('*** [%s] %s ***', get_called_class(), __FUNCTION__));
        return $this->start($request, $exception);
    }
    
    public function start(Request $request, AuthenticationException $authException = null)
    {
        $this->logger->debug(sprintf('*** [%s] %s ***', get_called_class(), __FUNCTION__));
        
        if ($this->shouldStartValidate($request)) {
            return $this->redirectToAuthorization(
                $request,
                $this->_getMicrosoftClientProvider()->getScopes()
            );
        }
    }
    
    protected function fetchAccessTokenByRefreshToken(string $refreshToken, array $options = [])
    {
        return $this->_getMicrosoftClient()->fetchAccessTokenByRefreshToken($refreshToken, $options);
    }

    protected function redirectToAuthorization(
        Request $request,
        array $scopes = []
    ) {
        $state = !empty($request->query->get('state')) ? $request->query->get('state') : $request->getPathInfo();
        
        return $this->_getMicrosoftClient()->redirect(
            $scopes,
            ['state' => $state]
        );
    }
    
    private function _getMicrosoftOAuthCredential($accessToken, $scopes = [])
    {
        $className = $this->getOAuthCredentialClass();
        return new $className($this->_getMicrosoftConfiguration(), $accessToken, $scopes);
    }

    private function _securityExists()
    {
        return ($this->security->getToken() !== null && $this->security->getUser() !== null);
    }

    private function _securityMicrosoftOAuthCredentialExists()
    {
        return $this->_securityExists() && isset(($this->security->getToken()->getAttributes())[$this->getOAuthCredentialKey()]);
    }

    private function _loadSecurityMicrosoftOAuthCredentialIfExists()
    {
        if ($this->_securityMicrosoftOAuthCredentialExists()) {
            $this->oAuthCredential = ($this->security->getToken()->getAttributes())[$this->getOAuthCredentialKey()];
        }
    }

    private function _getMicrosoftClient()
    {
        return $this->clientRegistry->getClient($this->getClientName());
    }

    private function _getMicrosoftClientProvider()
    {
        return $this->_getMicrosoftClient()->getOAuth2Provider();
    }
    
    private function _getMicrosoftConfiguration()
    {
        return $this->_getMicrosoftClientProvider()->getMicrosoftConfiguration();
    }
    
    private function shouldStartValidate(Request $request)
    {
        return (
            $request->attributes->get('_route') === $this->getConnectPath() ||
            !$this->_securityExists() ||
            (
                $this->oAuthCredential !== null &&
                $this->oAuthCredential->isExpired() &&
                !$this->oAuthCredential->canRefreshToken()
            )
        );
    }
}