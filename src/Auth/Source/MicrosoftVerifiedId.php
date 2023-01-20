<?php

namespace SimpleSAML\Module\msverifiedid\Auth\Source;

use SimpleSAML\Assert\AssertionFailedException;
use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\Module;
use SimpleSAML\Utils;
use SimpleSAML\Logger;
use SimpleSAML\Session;
use SimpleSAML\Store\StoreFactory;
use SimpleSAML\Store\StoreInterface;
use SimpleSAML\Module\msverifiedid\MicrosoftVerifiedId\AttributeManipulator;
use SimpleSAML\Module\msverifiedid\MicrosoftVerifiedId\StateData;

/**
 * Microsoft Entra Verified ID authentication source.
 *
 * @package SimpleSAMLphp
 */
class MicrosoftVerifiedId extends Auth\Source
{
    /**
     * The key of the AuthID field in the state.
     */
    public const AUTHID = 'msverifiedid:AuthID';

    /**
     * The value we use in data store to indicate
     * that a VC presentation request has been retrieved,
     * but not yet verified
     */
    public const PRES_REQ_RETRIEVED_STR_VAL = 'IN_PROCESS';

    /**
     * The constant value we return to indicate
     * that VC presentation request is pending
     * (neither retrieved nor verified)
     */
    public const PRES_REQ_PENDING = 0;

    /**
     * The constant value we return to indicate
     * that VC presentation request has been
     * retrieved, but not verified
     */
    public const PRES_REQ_RETRIEVED = 1;

    /**
     * The constant value we return to indicate
     * that VC presentation request has been
     * retrieved and verified
     */
    public const PRES_REQ_VERIFIED = 2;

    /**
     * Lifetime for stored data (needed for MS API callback)
     * in seconds
     */
    public const STORED_DATA_LIFETIME = 900;

    /**
     * An object with all the parameters that will be needed in the authentication module
     *
     * @var Module\msverifiedid\MicrosoftVerifiedId\StateData
     */
    private StateData $stateData;

    /**
     * @var \SimpleSAML\Configuration
     */
    protected $config;


    /**
     * Constructor for this authentication source.
     *
     * @param array $info  Information about this authentication source.
     * @param array $config  Configuration.
     */
    public function __construct($info, $config)
    {
        parent::__construct($info, $config);

        $this->config = Configuration::loadFromArray($config, 'authsources:msverifiedid');

        $this->stateData = new StateData();

        $moduleConfig = Configuration::getConfig('module_msverifiedid.php');

        try {
            $this->stateData->clientId = $moduleConfig->getString('client_id');
        } catch (AssertionFailedException $e) {
            throw new Error\CriticalConfigurationError('msverifiedid: it is required to set client_id in config.');
        }

        try {
            $this->stateData->clientSecret = $moduleConfig->getString('client_secret');
        } catch (AssertionFailedException $e) {
            throw new Error\CriticalConfigurationError('msverifiedid: it is required to set client_secret in config.');
        }

        try {
            $this->stateData->tenantId = $moduleConfig->getString('tenant_id');
        } catch (AssertionFailedException $e) {
            throw new Error\CriticalConfigurationError('msverifiedid: it is required to set tenant_id in config.');
        }

        try {
            $this->stateData->verifierId = $moduleConfig->getString('verifier_id');
        } catch (AssertionFailedException $e) {
            throw new Error\CriticalConfigurationError('msverifiedid: it is required to set verifier_id in config.');
        }

        try {
            $this->stateData->verifierClientName = $moduleConfig->getString('verifier_client_name');
        } catch (AssertionFailedException $e) {
            throw new Error\CriticalConfigurationError(
                'msverifiedid: it is required to set verifier_client_name in config.'
            );
        }

        try {
            $this->stateData->verifiableCredentialType = $moduleConfig->getString('verifiable_credential_type');
        } catch (AssertionFailedException $e) {
            throw new Error\CriticalConfigurationError(
                'msverifiedid: it is required to set verifiable_credential_type in config.'
            );
        }

        try {
            $this->stateData->acceptedIssuerIds = $moduleConfig->getArray('accepted_issuer_ids');
        } catch (AssertionFailedException $e) {
            throw new Error\CriticalConfigurationError(
                'msverifiedid: it is required to set accepted_issuer_ids in config.'
            );
        }

        try {
            $this->stateData->scope = $moduleConfig->getOptionalString(
                'scope',
                '3db474b9-6a0c-4840-96ac-1fceb342124f/.default'
            );
        } catch (AssertionFailedException $e) {
            throw new Error\CriticalConfigurationError('msverifiedid: invalid value for scope in config.');
        }

        try {
            $this->stateData->verifierRequestPurpose = $moduleConfig->getOptionalString('verifier_request_purpose', '');
        } catch (AssertionFailedException $e) {
            throw new Error\CriticalConfigurationError(
                'msverifiedid: invalid value for verifier_request_purpose in config.'
            );
        }

        try {
            $this->stateData->allowRevoked = $moduleConfig->getOptionalBoolean('allow_revoked', false);
        } catch (AssertionFailedException $e) {
            throw new Error\CriticalConfigurationError('msverifiedid: invalid value for allow_revoked in config.');
        }

        try {
            $this->stateData->validateLinkedDomain = $moduleConfig->getOptionalBoolean('validate_linked_domain', true);
        } catch (AssertionFailedException $e) {
            throw new Error\CriticalConfigurationError(
                'msverifiedid: invalid value for validate_linked_domain in config.'
            );
        }

        try {
            $this->stateData->msApiBaseUrl = $moduleConfig->getOptionalString(
                'ms_api_base_url',
                'https://verifiedid.did.msidentity.com/v1.0/'
            );
        } catch (AssertionFailedException $e) {
            throw new Error\CriticalConfigurationError('msverifiedid: invalid value for ms_api_base_url in config.');
        }
    }

    /**
     * Retrieve attributes for the user.
     *
     * @return array|null  The user's attributes from Verified ID presentation response,
     * or NULL if the user isn't authenticated.
     */
    private function getUser(): ?array
    {
        $claims = Session::getSessionFromRequest()->getData('array', 'claims');
        if (is_null($claims)) {
            // The user isn't authenticated
            return null;
        }

        $attributeManipulator = new AttributeManipulator();
        return $attributeManipulator->prefixAndFlatten($claims, $this->getAttributePrefix());
    }

    /**
     * Log in using an external authentication helper.
     *
     * @param array &$state  Information about the current authentication.
     * @return void
     */
    public function authenticate(array &$state): void
    {
        $requester = "Unknown";
        if (isset($state['saml:RequesterID'])) {
            $requester = implode(",", $state['saml:RequesterID']);
        }
        Logger::notice("MS Verified ID Requester: $requester");

        $attributes = $this->getUser();
        if ($attributes !== null) {
            /*
             * The user is already authenticated.
             *
             * Add the users attributes to the $state-array, and return control
             * to the authentication process.
             */
            $state['Attributes'] = $attributes;
            return;
        }

        $state[self::AUTHID] = $this->authId;
        $stateId = Auth\State::saveState($state, 'msverifiedid:Verify');

        $returnTo = Module::getModuleURL('msverifiedid/resume', [
            'StateId' => $stateId,
        ]);
        $verifyPage = Module::getModuleURL('msverifiedid/verify', [
            'StateId' => $stateId,
        ]);
        $httpUtils = new Utils\HTTP();
        $httpUtils->redirectTrustedURL($verifyPage, [
            'StateId' => $stateId,
            'ReturnTo' => $returnTo,
        ]);

        /*
         * The redirect function never returns, so we never get this far.
         */
        assert(false);
    }

    /**
     * Resume authentication process.
     *
     * This function resumes the authentication process after the user has
     * successfully presented a Verified ID.
     *
     * @param array $state
     * @return void
     * @throws \SimpleSAML\Error\NoState
     * @throws \SimpleSAML\Error\Exception
     */
    public static function resume($state)
    {
        /* Find authentication source. */
        assert(array_key_exists(self::AUTHID, $state));

        $source = \SimpleSAML\Auth\Source::getById($state[self::AUTHID]);
        if ($source === null) {
            throw new \Exception('Could not find authentication source with id ' . $state[self::AUTHID]);
        }

        if (!($source instanceof self)) {
            throw new Error\Exception('Authentication source type changed.');
        }

        $attributes = $source->getUser();
        if ($attributes === null) {
            throw new Error\Exception('User not authenticated after login page.');
        }

        $state['Attributes'] = $attributes;
        Auth\Source::completeAuth($state);

        /*
         * The completeAuth-function never returns, so we never get this far.
         */
        assert(false);
    }

    /**
     * Handle request for Verified ID Presentation
     *
     * This function requests a new openid-vc URL and returns
     * the needed info to render the QR code or, on mobile platforms,
     * to open a deep link in Microsoft Authenticator.
     *
     * @param array $state
     * @param string $opaqueId
     * @param string $apiKey
     * @param \SimpleSAML\Module\msverifiedid\MicrosoftVerifiedId\PresentationRequestHelper $presReqHelper
     * @return string url
     * @throws \SimpleSAML\Error\NoState
     * @throws \SimpleSAML\Error\Exception
     */
    public static function handleVerifyRequest(
        $state,
        $opaqueId,
        $apiKey,
        $presReqHelper
    ) {
        /* Find authentication source. */
        assert(array_key_exists(self::AUTHID, $state));

        $source = \SimpleSAML\Auth\Source::getById($state[self::AUTHID]);
        if ($source === null) {
            throw new \Exception('Could not find authentication source with id ' . $state[self::AUTHID]);
        }

        if (!($source instanceof self)) {
            throw new Error\Exception('Authentication source type changed.');
        }

        /* Store API key indexed by opaqueId */
        self::getStore()->set(
            'array',
            "msverifiedid-$opaqueId",
            ['apiKey' => $apiKey],
            time() + self::STORED_DATA_LIFETIME
        );

        // initiate VC presentation request
        $presUrl = $presReqHelper->initPresentationRequest(
            $source->stateData,
            $opaqueId,
            $apiKey
        );
        Logger::debug("*** VC presentation URL = " . $presUrl);
        return $presUrl;
    }

    /**
     * Handle login
     *
     * This function handles the login after successfully
     * completing the credentials verification process
     *
     * @param array $state
     * @param string $opaqueId
     * @param string $returnTo
     * @return bool
     * @throws \SimpleSAML\Error\Exception
     */
    public static function handleLogin($state, $opaqueId)
    {
        /* Find authentication source. */
        assert(array_key_exists(self::AUTHID, $state));

        $source = \SimpleSAML\Auth\Source::getById($state[self::AUTHID]);
        if ($source === null) {
            throw new \Exception('Could not find authentication source with id ' . $state[self::AUTHID]);
        }

        if (!($source instanceof self)) {
            throw new Error\Exception('Authentication source type changed.');
        }

        $storedData = self::getStore()->get('array', "msverifiedid-$opaqueId");
        if ($storedData !== null && array_key_exists('claims', $storedData) && $storedData['claims'] !== null) {
            Session::getSessionFromRequest()->setData('array', 'claims', $storedData['claims']);
            return true;
        }
        Logger::error("credential verification failed");
        return false;
    }

    /**
     * Handle status check
     *
     * This function handles the status check AJAX call
     * from the browser to determine if verification completed
     *
     * @param array $state
     * @param string $opaqueId
     * @return int
     * @throws \SimpleSAML\Error\NoState
     * @throws \SimpleSAML\Error\Exception
     */
    public static function handleStatusCheck($state, $opaqueId)
    {
        /* Find authentication source. */
        assert(array_key_exists(self::AUTHID, $state));

        $source = \SimpleSAML\Auth\Source::getById($state[self::AUTHID]);
        if ($source === null) {
            throw new \Exception('Could not find authentication source with id ' . $state[self::AUTHID]);
        }

        if (!($source instanceof self)) {
            throw new Error\Exception('Authentication source type changed.');
        }

        $storedData = self::getStore()->get('array', "msverifiedid-$opaqueId");
        if ($storedData === null) {
            throw new Error\Exception("Could not retrieve storage for opaqueId $opaqueId.");
        }
        if (!array_key_exists('claims', $storedData)) {
            return self::PRES_REQ_PENDING;
        } elseif ($storedData['claims'] === self::PRES_REQ_RETRIEVED_STR_VAL) {
            return self::PRES_REQ_RETRIEVED;
        } else {
            return self::PRES_REQ_VERIFIED;
        }
    }

    /**
     * Handle MS API callback
     *
     * This method is called by the VC Request API when the user scans a QR code
     * and presents a Verifiable Credential to the service
     *
     * @param array  $body      Parsed JSON request body from MS API callback
     * @param string|null $apiKey    API Key passed from MS API callback
     * @return bool
     * @throws \SimpleSAML\Error\NoState
     * @throws \SimpleSAML\Error\Exception
     */
    public static function handleCallback($body, $apiKey)
    {
        /* Get opaqueId from 'state' property in JSON body */
        $opaqueId = null;
        if (array_key_exists('state', $body)) {
            $opaqueId = $body['state'];
        }
        /* Retrieve stored API Key and claims by opaqueId */
        $store = self::getStore();
        $storedData = $store->get('array', "msverifiedid-$opaqueId");

        if ($storedData !== null) {
            /* Ensure API key returned by MS is the same one we initially set */
            if (array_key_exists('apiKey', $storedData) && $storedData['apiKey'] === $apiKey) {
                $claims = null;
                if (array_key_exists('claims', $storedData)) {
                    $claims = $storedData['claims'];
                }
                if (
                    $claims === null &&
                    array_key_exists('requestStatus', $body) &&
                    $body['requestStatus'] === 'request_retrieved'
                ) {
                    // this is the first callback, so store "retrieved" placeholder value
                    $storedData['claims'] = self::PRES_REQ_RETRIEVED_STR_VAL;
                    $store->set('array', "msverifiedid-$opaqueId", $storedData, time() + self::STORED_DATA_LIFETIME);
                    return true;
                } elseif (
                    $claims === self::PRES_REQ_RETRIEVED_STR_VAL &&
                    array_key_exists('requestStatus', $body) &&
                    $body['requestStatus'] === 'presentation_verified'
                ) {
                    // this is the second callback, so store the claims
                    $storedData['claims'] = $body['verifiedCredentialsData'][0]['claims'];
                    $store->set('array', "msverifiedid-$opaqueId", $storedData, time() + self::STORED_DATA_LIFETIME);
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Handle stop
     *
     * This function handles cancellation of the
     * process by returning a SAML Error Response
     *
     * @param array $state
     * @return void
     * @throws \SimpleSAML\Error\NoState
     * @throws \SimpleSAML\Error\Error
     */
    public static function handleStop($state)
    {
        Logger::notice("Authentication stopped");

        Auth\State::throwException(
            $state,
            new \SimpleSAML\Module\saml\Error(
                \SAML2\Constants::STATUS_RESPONDER,
                \SAML2\Constants::STATUS_AUTHN_FAILED,
                'Authentication failed'
            )
        );
    }

    /**
     * This function is called when the user start a logout operation, for example
     * by logging out of a SP that supports single logout.
     *
     * @param array &$state The logout state array.
     * @return void
     */
    public function logout(array &$state): void
    {
        /*
         * delete claims from session
         */
        Session::getSessionFromRequest()->deleteData('array', 'claims');

        /*
         * If we need to do a redirect to a different page, we could do this
         * here, but in this example we don't need to do this.
         */
    }

    public static function getStore(): StoreInterface
    {
        $config = Configuration::getInstance();
        $storeType = $config->getOptionalString('store.type', 'phpsession');
        $store = StoreFactory::getInstance($storeType);
        assert($store !== false, "Store must be configured");
        return $store;
    }

    protected function getAttributePrefix(): string
    {
        return $this->config->getOptionalString('attributePrefix', '');
    }
}
