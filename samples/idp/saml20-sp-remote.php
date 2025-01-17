<?php

/**
 * SAML 2.0 SP configuration for SimpleSAMLphp.
 *
 * See: https://simplesamlphp.org/docs/stable/simplesamlphp-reference-sp-remote
 */

$metadata['https://sp.college.edu/sp'] = [
    'AssertionConsumerService' => [
        [
            'index' => 1,
            'isDefault' => true,
            'Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
            'Location' => 'https://your-ngrok-forwarding-url.ngrok.io/sample-idp/module.php/saml/sp/saml2-acs.php/default-sp'
        ]
    ]
];
