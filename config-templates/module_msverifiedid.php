<?php

$config = [
    /* required configuration parameters */

    // Azure app client ID
    'client_id' => '819255d9-7aaa-47f3-b025-bd4aa6af52f0',
    // Azure app client secret
    'client_secret' => 'Xg98Q~w3LUcqjELreAJAddfNwsZN1Ax5~3WB~cX2',
    // Azure AD tenant ID
    'tenant_id' => '5c8b71e9-6b28-4bfd-9bf5-c44c7883ac22',
    // registered verifier ID -- starts with "did:web:" or "did:ion:"
    'verifier_id' => 'did:web:www.athena-institute.net',
    // A display name of the verifier of the verifiable credential.
    // This name will be presented to the user in the authenticator app.
    'verifier_client_name' => 'Veriable Credential Expert Verifier',
    // The verifiable credential type. The type must match the type
    // as defined in the issuer verifiable credential manifest
    // (for example, VerifiedCredentialExpert).
    'verifier_credential_type' => 'VerifiedCredentialExpert',
    // A collection of issuers' DIDs that could issue the type
    // of verifiable credential that subjects can present. 
    'accepted_issuer_ids' => ['did:web:www.athena-institute.net'],

    /* optional configuration parameters */

    // Important: At this moment the scope needs to be:
    // 3db474b9-6a0c-4840-96ac-1fceb342124f/.default
    // This might change in the future
    'scope' => '3db474b9-6a0c-4840-96ac-1fceb342124f/.default',

    // Provide information about the purpose of requesting
    // this verifiable credential. Does not appear to be presented
    // to user in MS Authenticator UI, so default is null
    'verifier_request_purpose' => null,

    // in case Verified ID REST API base URL needs to be overridden
    // for other tenant regions
    'ms_api_base_url' => 'https://verifiedid.did.msidentity.com/v1.0/',

    // determines if a revoked credential should be accepted
    'allow_revoked' => false,

    // determines if the linked domain should be validated
    'validate_linked_domain' => true,
];
