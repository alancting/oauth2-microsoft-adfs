<?php

namespace Alancting\OAuth2\OpenId\Client\Client;

use Alancting\OAuth2\OpenId\Client\Client\AbstractMicrosoftClient;

class AdfsClient extends AbstractMicrosoftClient
{
    public function getClientKey()
    {
        return 'adfs_oauth';
    }
}