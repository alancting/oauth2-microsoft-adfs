<?php

namespace Alancting\OAuth2\OpenId\Client\ResourceOwner;

use League\OAuth2\Client\Provider\ResourceOwnerInterface;

// https://adfs.example.com/adfs/userinfo

class AdfsResourceOwner implements ResourceOwnerInterface
{
    /**
     * Raw response
     *
     * @var array
     */
    protected $response;

    /**
     * Creates new resource owner.
     *
     * @param array $response
     */
    public function __construct(array $response = array())
    {
        $this->response = $response;
    }

    /**
     * Get user id (sub)
     *
     * @return string|null
     */
    public function getId()
    {
        return $this->getSub();
    }

    /**
     * Get sub (client ID + anchor claim value)
     *
     * @return string|null
     */
    public function getSub()
    {
        return $this->response['sub'] ?: null;
    }

    /**
     * Return all of the owner details available as an array.
     *
     * @return array
     */
    public function toArray()
    {
        return $this->response;
    }
}