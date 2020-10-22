<?php

namespace Alancting\OAuth2\Client;

use Symfony\Component\HttpKernel\Bundle\Bundle;
use Alancting\OAuth2\Client\DependencyInjection\MicrosoftExtension;

class MicrosoftBundle extends Bundle
{
    public function getContainerExtension()
    {
        if (null === $this->extension) {
            return new MicrosoftExtension();
        }

        return $this->extension;
    }
}