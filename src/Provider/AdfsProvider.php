<?php

namespace Alancting\OAuth2\Client\Provider;

use Alancting\OAuth2\Client\Provider\AbstractMicrosoftProvider;
use Alancting\OAuth2\Client\ResourceOwner\AdfsResourceOwner;

use Alancting\Microsoft\JWT\Adfs\AdfsConfiguration;

use League\OAuth2\Client\Token\AccessToken;

use \UnexpectedValueException;

class AdfsProvider extends AbstractMicrosoftProvider
{
    public function __construct(array $options = [], array $collaborators = [])
    {
        if (!isset($options['hostname'])) {
            throw new UnexpectedValueException('Missing hostname');
        }
        
        parent::__construct($options, $collaborators);
    }
    
    protected function getResourceOwnernClass()
    {
        return 'Alancting\OAuth2\Client\ResourceOwner\AdfsResourceOwner';
    }

    protected function getMicrosoftConfigurationClass()
    {
        return 'Alancting\Microsoft\JWT\Adfs\AdfsConfiguration';
    }
}