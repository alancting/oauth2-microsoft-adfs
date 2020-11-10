<?php

namespace Alancting\OAuth2\OpenId\Client\Provider;

use \UnexpectedValueException;

class AzureAdProvider extends AbstractMicrosoftProvider
{
    public function __construct(array $options = [], array $collaborators = [])
    {
        if (!isset($options['tenant'])) {
            throw new UnexpectedValueException('Missing tenant');
        }

        if (!isset($options['tenant_id'])) {
            throw new UnexpectedValueException('Missing tenant_id');
        }

        parent::__construct($options, $collaborators);
    }

    protected function getResourceOwnernClass()
    {
        return 'Alancting\OAuth2\OpenId\Client\ResourceOwner\AzureAdResourceOwner';
    }

    protected function getMicrosoftConfigurationClass()
    {
        return 'Alancting\Microsoft\JWT\AzureAd\AzureAdConfiguration';
    }
}