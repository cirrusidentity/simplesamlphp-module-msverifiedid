# Microsoft Entra Verified ID auth module

This module adds Microsoft Entra Verified ID as auth source to simpleSAMLphp.

## Disclaimer
This module was not created by Microsoft and will not be supported by them. Please use [github issues](https://github.com/windhamg/simplesamlphp-module-msverifiedid/issues/new) for any questions about this module.


## Install

Install with composer

```bash
    vendor/bin/composer require windhamg/simplesamlphp-module-msverifiedid
```

## Configuration

Next thing you need to do is to enable the module: in `config.php`,
search for the `module.enable` key and set `authorize` to true:

```php
    'module.enable' => [
        'authorize' => true,
        …
    ],
```
