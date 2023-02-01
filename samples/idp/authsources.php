<?php

$config = [

    'msverifiedid-test' => [
        'msverifiedid:MicrosoftVerifiedId',
        'attributePrefix' => 'vc.'
    ],

    'default-sp' => [
        'saml:SP',
        'entityID' => 'https://sp.college.edu/sp',
        'privatekey' => 'server.pem',
        'certificate' => 'server.crt',
        'idp' => 'urn:msverifiedid:idp',
        'AssertionConsumerService' => [
            [
                'index' => 0,
                'isDefault' => true,
                'Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
                'Location' => 'https://your-ngrok-forwarding-url.ngrok.io/sample-idp/module.php/saml/sp/saml2-acs.php/default-sp'
            ]
        ]
    ],

    // This is a authentication source which handles admin authentication.
    'admin' => [
        // The default is to use core:AdminPassword, but it can be replaced with
        // any authentication source.

        'core:AdminPassword'
    ],

];