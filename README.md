[![Packagist](https://img.shields.io/packagist/v/alancting/oauth2-microsoft-openid?style=for-the-badge)](https://packagist.org/packages/alancting/oauth2-microsoft-openid)
[![GitHub](https://img.shields.io/github/v/release/alancting/oauth2-microsoft-openid?label=GitHub&style=for-the-badge)](https://github.com/alancting/oauth2-microsoft-openid)
[![Test](https://img.shields.io/github/workflow/status/alancting/oauth2-microsoft-openid/PHP%20Test?label=TEST&style=for-the-badge)](https://github.com/alancting/oauth2-microsoft-openid)
[![Coverage Status](https://img.shields.io/coveralls/github/alancting/oauth2-microsoft-openid/master?style=for-the-badge)](https://coveralls.io/github/alancting/oauth2-microsoft-openid?branch=master)
[![GitHub license](https://img.shields.io/github/license/alancting/oauth2-microsoft-openid?color=green&style=for-the-badge)](https://github.com/alancting/oauth2-microsoft-openid/blob/master/LICENCE)

# Microsoft Adfs / AzureAD OpenId Integration for Symfony

Microsoft Azure Active Directory (Azure AD), Microsoft Active Directory Federation Services (Adfs) OpenId Integration for Symfony

- Login with Adfs / AzureAd
  - All token handling is wrapped in the guard authenticator
- Easy to get the stored tokens from a registered service

This bundle integrates with [knpuniversity/oauth2-client-bundle](https://github.com/knpuniversity/oauth2-client-bundle)

This package provides Microsoft OAuth 2.0 support for the PHP League's [OAuth 2.0 Client](https://github.com/thephpleague/oauth2-client).

**Forked From [stevenmaguire/oauth2-microsoft](https://github.com/stevenmaguire/oauth2-microsoft)**

## Installation

To install, use composer:

```
composer require alancting/oauth2-microsoft-openid
```

## Get Start

### Step 1 - Include in the bundles

```php
# config/bundles.php
return [
    Symfony\Bundle\FrameworkBundle\FrameworkBundle::class => ['all' => true],
    ...
    Alancting\OAuth2\OpenId\Client\MicrosoftBundle::class => ['all' => true],
];
```

### Step 2 - Configure the provider

We make use of the configuration from [knpuniversity/oauth2-client-bundle](https://github.com/knpuniversity/oauth2-client-bundle#configuration)

#### Adfs

```yml
# config/packages/knpu_oauth2_client.yaml
knpu_oauth2_client:
  clients:
    microsoft_openid:
      type: generic
      provider_class: Alancting\OAuth2\OpenId\Client\Provider\AdfsProvider
      client_class: Alancting\OAuth2\OpenId\Client\Client\AdfsClient
      client_id: "%env(ADFS_CLIENT_ID)%"
      client_secret: "%env(ADFS_CLIENT_SECRET)%"
      redirect_route: microsoft_openid_connect
      provider_options:
        hostname: "%env(ADFS_HOSTNAME)%"
        user_key: unique_name
        microsoft_resource_scopes:
          - profile
          - offline_access
        other_resource_scopes:
          - "%env(ADFS_API_RESOURCE_1)%"
          - "%env(ADFS_API_RESOURCE_2)%"
```

#### Azure Ad

```yaml
# config/packages/knpu_oauth2_client.yaml
knpu_oauth2_client:
  clients:
    microsoft_openid:
      type: generic
      provider_class: Alancting\OAuth2\OpenId\Client\Provider\AzureAdProvider
      client_class: Alancting\OAuth2\OpenId\Client\Client\AzureAdClient
      client_id: "%env(AZURE_AD_CLIENT_ID)%"
      client_secret: "%env(AZURE_AD_CLIENT_SECRET)%"
      redirect_route: microsoft_openid_connect
      provider_options:
        tenant: "%env(AZURE_AD_TENANT)%"
        tenant_id: "%env(AZURE_AD_TENANT_ID)%"
        user_key: upn
        microsoft_resource_scopes:
          - profile
          - offline_access
        other_resource_scopes:
          - "%env(AZURE_AD_API_RESOURCE_1)%"
          - "%env(AZURE_AD_API_RESOURCE_2)%"
```

### Step 3 - Configure the use authenticator

#### Adfs

```yaml
# config/packages/security.yaml
secure_firewall:
    pattern: ^/([a-z])
      anonymous: ~
      logout:
        path: microsoft_openid_logout
        success_handler: App\Utility\LogoutHandler
      guard:
        provider: microsoft_openid_oauth
        authenticators:
          - alancting.microsoft.adfs.authenticator
```

#### Azure Ad

```yaml
# config/packages/security.yaml
secure_firewall:
    pattern: ^/([a-z])
      anonymous: ~
      logout:
        path: microsoft_openid_logout
        success_handler: App\Utility\LogoutHandler
      guard:
        provider: microsoft_openid_oauth
        authenticators:
          - alancting.microsoft.azure_ad.authenticator
```

### Step 4 - Register pathsserver

We need to register two path to communicate with the OAuth2 server

1. connect
2. logout

#### Adfs

```php
namespace App\Controller;

use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\HttpFoundation\Response;

class AzureAdController extends AbstractController
{
    /**
     * After going to microsoft, you're redirected back here
     * because this is the "redirect_route" you configured
     * in config/packages/knpu_oauth2_client.yaml
     *
     * @Route("/adfs/connect", name="microsoft_openid_connect")
     */
    public function connectCheckAction(Request $request, ClientRegistry $clientRegistry)
    {
        return new Response();
    }

    /**
     * After going to microsoft, you're redirected back here
     * because this is the "redirect_route" you configured
     * in config/packages/knpu_oauth2_client.yaml
     *
     * @Route("/adfs/logout", name="microsoft_openid_logout")
     */
    public function logoutAction(Request $request, ClientRegistry $clientRegistry)
    {
        return new Response();
    }
}
```

#### Azure Ad

```php
namespace App\Controller;

use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\HttpFoundation\Response;

class AzureAdController extends AbstractController
{
    /**
     * After going to microsoft, you're redirected back here
     * because this is the "redirect_route" you configured
     * in config/packages/knpu_oauth2_client.yaml
     *
     * @Route("/azure_ad/connect", name="microsoft_openid_connect")
     */
    public function connectCheckAction(Request $request, ClientRegistry $clientRegistry)
    {
        return new Response();
    }

    /**
     * After going to microsoft, you're redirected back here
     * because this is the "redirect_route" you configured
     * in config/packages/knpu_oauth2_client.yaml
     *
     * @Route("/azure_ad/logout", name="microsoft_openid_logout")
     */
    public function logoutAction(Request $request, ClientRegistry $clientRegistry)
    {
        return new Response();
    }
}
```

### Usage

After user login, you can get the login credentials

#### Adfs

```php
use Alancting\OAuth2\OpenId\Client\Client\AdfsClient;

public index(AdfsClient $adfsClient)
{
    /**
     * Get credential for main scope
     */
    $mainScopeCredential = $adfsClient->getOAuthCredential();

    // Get access token
    $accessToken = $mainScopeCredential->getAccessToken();
    // Get id token
    $idTokenJWT = $mainScopeCredential->getIdTokenJWT();
    // Get id token payload
    $idTokenPayload = $idTokenJWT->getPayload();
    // Get value for a specific attr from id token payload
    $idTokenPayloadAttr1 = $idTokenJWT->get('attr1');

    /**
     * If have other resource scopes, you can loop to fetch credentials for other scopes
     */
    $otherScopeCredentials = [];
    foreach ($mainScopeCredential->getOtherResourceCredentials() as $scope => $credential) {
        $otherScopeCredentials[$scope] = $credential;
    }

    /**
     * You can also get the credential from scope name by
     */
    $otherScopeCredential = $mainScopeCredential->getOtherResourceCredential('other_scope_name');
}
```

#### Azure Ad

```php
use Alancting\OAuth2\OpenId\Client\Client\AzureAdClient;

public index(AzureAdClient $azureAdClient)
{
    /**
     * Get credential for main scope
     */
    $mainScopeCredential = $azureAdClient->getOAuthCredential();

    // Get access token
    $accessToken = $mainScopeCredential->getAccessToken();
    // Get id token
    $idTokenJWT = $mainScopeCredential->getIdTokenJWT();
    // Get id token payload
    $idTokenPayload = $idTokenJWT->getPayload();
    // Get value for a specific attr from id token payload
    $idTokenPayloadAttr1 = $idTokenJWT->get('attr1');

    /**
     * If have other resource scopes, you can loop to fetch credentials for other scopes
     */
    $otherScopeCredentials = [];
    foreach ($mainScopeCredential->getOtherResourceCredentials() as $scope => $credential) {
        $otherScopeCredentials[$scope] = $credential;
    }

    /**
     * You can also get the credential from scope name by
     */
    $otherScopeCredential = $mainScopeCredential->getOtherResourceCredential('other_scope_name');
}
```

#### Logout Handling

In symfony, to logout a user, you should use

- 4.4: Logout success handler
- 5.x+: Logout event

After your app go to logout handler / event, you should redirect user to the Adfs / Azure AD logout Url, you can get the url by

```php
// Logout url for Adfs
$logoutUrl = $adfsClient->getLogoutUrl();

// Logout url for Azure Ad
$logoutUrl = $azureAdClient->getLogoutUrl();
```

## Tests

Run the tests using phpunit:

```bash
$ composer install
$ composer run test
```

## Contributing

Please see [CONTRIBUTING](https://github.com/alancting/oauth2-microsoft-openid/blob/master/CONTRIBUTING.md) for details.

## Credits

- [Steven Maguire](https://github.com/stevenmaguire)
- [All Contributors](https://github.com/stevenmaguire/oauth2-microsoft/contributors)

## License

The MIT License (MIT). Please see [License File](https://github.com/alancting/oauth2-microsoft-openid/blob/master/LICENSE) for more information.
