<?php

namespace Alancting\OAuth2\OpenId\Client\Provider;

use League\OAuth2\Client\Provider\AbstractProvider;
use GuzzleHttp\Psr7\Uri;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use Psr\Http\Message\ResponseInterface;

use \UnexpectedValueException;

abstract class AbstractMicrosoftProvider extends AbstractProvider
{
    abstract protected function getResourceOwnernClass();
    abstract protected function getMicrosoftConfigurationClass();

    public $defaultScopes = ['openid'];

    private $_microsoftConfiguration;

    protected $microsoftResourceScopes;
    protected $otherResourceScopes;

    protected $userKey;

    public function __construct(array $options = [], array $collaborators = [])
    {
        if (!isset($options['user_key'])) {
            throw new UnexpectedValueException('Missing user_key');
        }

        $options['client_id'] = $options['clientId'];
        $options['client_secret'] = $options['clientSecret'];

        $configuration_class_name = $this->getMicrosoftConfigurationClass();
        $this->_microsoftConfiguration = new $configuration_class_name($options);

        $loadStatus = $this->_microsoftConfiguration->getLoadStatus();
        if (!$loadStatus['status']) {
            throw new UnexpectedValueException($loadStatus['error']);
        }

        $this->microsoftResourceScopes = isset($options['microsoft_resource_scopes']) ? $options['microsoft_resource_scopes'] : [];
        $this->otherResourceScopes= isset($options['other_resource_scopes']) ? $options['other_resource_scopes'] : [];

        $this->userKey = $options['user_key'];

        parent::__construct($options, $collaborators);
    }

    public function getUserKey()
    {
        return $this->userKey;
    }

    public function getBaseAuthorizationUrl()
    {
        return $this->_microsoftConfiguration->getAuthorizationEndpoint();
    }

    public function getBaseAccessTokenUrl(array $params)
    {
        return $this->_microsoftConfiguration->getTokenEndpoint();
    }

    public function getResourceOwnerDetailsUrl(AccessToken $token)
    {
        $uri = new Uri($this->_microsoftConfiguration->getUserInfoEndpoint());

        return (string) Uri::withQueryValue($uri, 'access_token', (string) $token->getToken());
    }

    public function getLogoutUrl(string $id_token = null, string $redirect_uri = null)
    {
        $uri = new Uri($this->_microsoftConfiguration->getEndSessionEndpoint());

        $params = [];
        if (!empty($id_token)) {
            $params['id_token_hint'] = (string) $id_token;
        }

        if (!empty($redirect_uri)) {
            $params['post_logout_redirect_uri'] = (string) $redirect_uri;
        }

        if (!empty($params)) {
            $uri = Uri::withQueryValues($uri, $params);
        }

        return $uri;
    }

    public function getScopes()
    {
        return array_merge($this->getDefaultScopes(), $this->microsoftResourceScopes);
    }

    public function getMicrosoftResourceScopes()
    {
        return $this->microsoftResourceScopes;
    }

    public function getOtherResourceScopes()
    {
        return $this->otherResourceScopes;
    }

    public function getMicrosoftConfiguration()
    {
        return $this->_microsoftConfiguration;
    }

    public function getDefaultScopes()
    {
        return $this->defaultScopes;
    }

    protected function checkResponse(ResponseInterface $response, $data)
    {
        if (isset($data['error']) || !in_array($response->getStatusCode(), [200,201])) {
            throw new IdentityProviderException(
                (isset($data['error']['message']) ? $data['error']['message'] : $response->getReasonPhrase()),
                $response->getStatusCode(),
                $response
            );
        }
    }

    protected function getScopeSeparator()
    {
        return ' ';
    }

    protected function createResourceOwner(array $response, AccessToken $token)
    {
        $class_name = $this->getResourceOwnernClass();

        return new $class_name($response);
    }

    protected function getAuthorizationHeaders($token = null)
    {
        return [
            'Authorization' => sprintf('Bearer %s', $token->getToken()),
        ];
    }
}