<?php

namespace SimpleSAML\Module\msverifiedid\Controller;

use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Module\msverifiedid\MicrosoftVerifiedId\PresentationRequestHelper;
use SimpleSAML\Session;
use SimpleSAML\Utils\HTTP;
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Ramsey\Uuid\Uuid;

/**
 * Controller class for the msverifiedid module.
 *
 * This class serves the different views available in the module.
 *
 * @package SimpleSAML\Module\msverifiedid
 */

class MicrosoftVerifiedId
{
    /** @var \SimpleSAML\Configuration */
    protected Configuration $config;

    /** @var \SimpleSAML\Session */
    protected \SimpleSAML\Session $session;

    /**
     * @var \SimpleSAML\Auth\State|string
     * @psalm-var \SimpleSAML\Auth\State|class-string
     */
    protected $authState = Auth\State::class;

    /**
     * @var \SimpleSAML\Module\msverifiedid\MicrosoftVerifiedId\PresentationRequestHelper
     */
    protected PresentationRequestHelper $presReqHelper;

    private ?HTTP $http = null;

    /**
     * Controller constructor.
     *
     * It initializes the global configuration and auth source configuration for the controllers implemented here.
     *
     * @param \SimpleSAML\Configuration              $config The configuration to use by the controllers.
     * @param \SimpleSAML\Session                    $session The session to use by the controllers.
     *
     * @throws \Exception
     */
    public function __construct(
        Configuration $config,
        Session $session
    ) {
        $this->config = $config;
        $this->session = $session;
        $this->presReqHelper = new PresentationRequestHelper();
    }

    /**
     * Inject the \SimpleSAML\Auth\State dependency.
     *
     * @param \SimpleSAML\Auth\State $authState
     */
    public function setAuthState(Auth\State $authState): void
    {
        $this->authState = $authState;
    }

    /**
     * Inject the \SimpleSAML\Module\msverifiedid\MicrosoftVerifiedId\PresentationRequestHelper dependency,
     * for injecting mock presentation request backend for testing
     *
     * @param \SimpleSAML\Module\msverifiedid\MicrosoftVerifiedId\PresentationRequestHelper $presReqHelper
     */
    public function setPresReqHelper(PresentationRequestHelper $presReqHelper): void
    {
        $this->presReqHelper = $presReqHelper;
    }

    /**
     * Callback handler for MS Verified ID API
     *
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @return \Symfony\Component\HttpFoundation\Response
     */
    public function callback(Request $request): Response
    {
        $apiKey = $request->headers->get('api-key', null);
        $body = $request->toArray();    // get JSON body
        $res = \SimpleSAML\Module\msverifiedid\Auth\Source\MicrosoftVerifiedId::handleCallback(
            $body,
            $apiKey
        );
        /* Check if callback was valid and respond appropriately */
        $response = new Response('', 200);
        if (!$res) {
            $response->setStatusCode(401);
            $response->setContent(json_encode([
                'error' => 'api-key wrong or missing'
            ]));
            $response->headers->set('Content-Type', 'application/json');
        }
        return $response;
    }

    /**
     * Return failure page
     *
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @return \SimpleSAML\XHTML\Template
     */
    public function failed(Request $request): Template
    {
        $t = new Template($this->config, 'msverifiedid:failed.twig');
        $t->setStatusCode(403);
        return $t;
    }

    /**
     * Controller method to invoke function to resume auth process
     * following successful VC presentation.
     *
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @return void
     */
    public function resume(Request $request): void
    {
        $stateId = strval($request->query->get('StateId'));
        if (!$stateId) {
            throw new Error\BadRequest('Missing required StateId query parameter.');
        }

        $state = $this->fetchAuthState($stateId);
        \SimpleSAML\Module\msverifiedid\Auth\Source\MicrosoftVerifiedId::resume($state);

        /*
         * The resume function should not return, so we never get this far.
         */
        assert(false);
    }

    /**
     * Return a simple HTTP status code response indicating status
     * of Verified Credentials verification request
     *
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @return \Symfony\Component\HttpFoundation\Response
     */
    public function status(Request $request): Response
    {
        $stateId = strval($request->query->get('StateId'));
        if (!$stateId) {
            throw new Error\BadRequest('Missing required StateId query parameter.');
        }
        $state = $this->fetchAuthState($stateId);

        $opaqueId = $this->session->getData('string', 'opaqueId');
        $status = \SimpleSAML\Module\msverifiedid\Auth\Source\MicrosoftVerifiedId::handleStatusCheck(
            $state,
            $opaqueId
        );
        switch ($status) {
            case \SimpleSAML\Module\msverifiedid\Auth\Source\MicrosoftVerifiedId::PRES_REQ_RETRIEVED:
                $statusCode = 202;
                break;
            case \SimpleSAML\Module\msverifiedid\Auth\Source\MicrosoftVerifiedId::PRES_REQ_VERIFIED:
                $statusCode = 201;
                break;
            default:
                $statusCode = 200;
        }
        $response = new Response('', $statusCode);
        return $response;
    }

    /**
     * Show a page with QR code (or deep link) for presenting a verified credential.
     *
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @return \SimpleSAML\XHTML\Template
     * @psalm-suppress InvalidReturnType
     * @psalm-suppress InternalMethod
     */
    public function verify(Request $request): Template
    {
        $stateId = $request->get('StateId');
        if (!$stateId) {
            throw new Error\BadRequest('Missing required StateId query parameter.');
        }
        $state = $this->fetchAuthState($stateId);

        $returnTo = $request->get('ReturnTo', false);
        if ($returnTo === false) {
            throw new Error\BadRequest('Missing required ReturnTo parameter.');
        }

        $httpUtils = new HTTP();
        $returnTo = $httpUtils->checkURLAllowed($returnTo);

        // time to handle login response
        if ($request->isMethod('POST')) {
            if ($request->request->get('action', null) === 'STOP') {
                \SimpleSAML\Module\msverifiedid\Auth\Source\MicrosoftVerifiedId::handleStop($state);
            }

            $opaqueId = $this->session->getData('string', 'opaqueId');
            if (\SimpleSAML\Module\msverifiedid\Auth\Source\MicrosoftVerifiedId::handleLogin(
                $state,
                $opaqueId
            )) {
               $this->getHttp()->redirectTrustedURL($returnTo);
            } else {
               $this->getHttp()->redirectTrustedURL(Module::getModuleURL('msverifiedid/failed'));
            }
        } else {
            // if we get this far, we need to show the verified ID presentation request page to the user

            /* opaque ID for identifying VC presentation request during callbacks */
            $opaqueId = Uuid::uuid4()->toString();
            /* Generate API key for authorize callback */
            $apiKey = Uuid::uuid4()->toString();

            $this->session->setData('string', 'opaqueId', $opaqueId);
            $this->session->setData('string', 'apiKey', $apiKey);

            $verifyUrl = \SimpleSAML\Module\msverifiedid\Auth\Source\MicrosoftVerifiedId::handleVerifyRequest(
                $state,
                $opaqueId,
                $apiKey,
                $this->presReqHelper
            );
            $statusUrl = Module::getModuleURL('msverifiedid/status', [
                'StateId' => $stateId,
            ]);

            $t = new Template($this->config, 'msverifiedid:verify.twig');
            $t->data['verify_url'] = $verifyUrl;
            $t->data['status_url'] = $statusUrl;
            $t->data['return_to_url'] = $returnTo;
            $t->data['state_id'] = $stateId;
            $t->setStatusCode(200);
            return $t;
        }
    }

    /**
     * Fetch current auth state
     *
     * @param string $stateId
     * @return array
     * @throws \SimpleSAML\Error\NoState
     */
    private function fetchAuthState($stateId): array
    {
        /* Retrieve the authentication state. */
        return $this->authState::loadState($stateId, 'msverifiedid:Verify');
    }

    /**
     * Used to allow tests to override
     * @return HTTP
     */
    public function getHttp(): HTTP
    {
        if (!isset($this->http)) {
            $this->http = new HTTP();
        }
        return $this->http;
    }

    /**
     * @param ?HTTP $http
     */
    public function setHttp(?HTTP $http): void
    {
        $this->http = $http;
    }
}
