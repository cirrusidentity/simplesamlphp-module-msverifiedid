# Microsoft Entra Verified ID auth module

This module adds Microsoft Entra Verified ID as auth source to simpleSAMLphp.

## Disclaimer
This module was not created by Microsoft and will not be supported by them. Please use [github issues](https://github.com/windhamg/simplesamlphp-module-msverifiedid/issues/new) for any questions about this module.


## Install

Install with composer

```bash
    composer require windhamg/simplesamlphp-module-msverifiedid
```

## Configuration

Ensure you are using something other than `phpsession` as the `store.type` value in `config.php` (e.g., `sql` or `memcache`). This is necessary due to the fact that Microsoft will make API callbacks to SSP, which are not tied to the user's SSP session.

Next thing you need to do is to enable the module: in `config.php`,
search for the `module.enable` key and set `authorize` to true:

```php
    'module.enable' => [
        'msverifiedid' => true,
        …
    ],
```

Add the authentication source to `authsource.php`:
```php
$config = [
...
    'msverifiedid' => [
        'msverifiedid:MicrosoftVerifiedId',
    ],
...
```

Then you need to copy `config-templates/module_msverifiedid.php` to your config directory and adjust settings accordingly. See the file for parameters description.

***TODO***: add lots more detail about setting-up Microsoft Entra Verified ID via the Azure portal.