<?php

namespace SimpleSAML\Module\msverifiedid\MicrosoftVerifiedId;

class StateData
{
    /**
     * Azure AD application (client) ID
     *
     * @var string
     */
    public string $clientId;

    /**
     * Azure AD application secret
     *
     * @var string
     */
    public string $clientSecret;

    /**
     * Azure AD tenant ID
     *
     * @var string
     */
    public string $tenantId;

    /**
     * Verifier ID to use in VC presentation requests
     *
     * @var string
     */
    public string $verifierId;

    /**
     * Verifier request registration client name to use in VC presentation requests
     *
     * @var string
     */
    public string $verifierClientName;

    /**
     * VC type being requested
     *
     * @var string
     */
    public string $verifiableCredentialType;

    /**
     * Purpose for requesting VC
     *
     * @var string|null
     */
    public ?string $verifierRequestPurpose = null;

    /**
     * Array of issuer IDs from which to accept VCs
     *
     * @var array
     */
    public array $acceptedIssuerIds;

    /**
     * Whether to allow revoked VCs
     *
     * @var bool
     */
    public bool $allowRevoked = false;

    /**
     * Whether linked domain should be validated
     *
     * @var bool
     */
    public bool $validateLinkedDomain = true;

    /**
     * OAuth2 scope for Verifiable Credentials Service Request
     *
     * @var string
     */
    public string $scope = '3db474b9-6a0c-4840-96ac-1fceb342124f/.default';

    /**
     * MS verified ID API base URL
     *
     * @var string
     */
    public string $msApiBaseUrl = 'https://verifiedid.did.msidentity.com/v1.0/';
}
