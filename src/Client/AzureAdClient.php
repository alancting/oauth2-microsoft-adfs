<?php

namespace Alancting\OAuth2\OpenId\Client\Client;

use Alancting\OAuth2\OpenId\Client\Client\AbstractMicrosoftClient;

class AzureAdClient extends AbstractMicrosoftClient
{
    public function getClientKey()
    {
        return 'azure_ad_oauth';
    }
}