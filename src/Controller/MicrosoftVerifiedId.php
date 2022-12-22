<?php

namespace SimpleSAML\Module\msverifiedid\Controller;

use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\Module;
use SimpleSAML\Session;
use SimpleSAML\Utils;
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\Request;
use Ramsey\Uuid\Uuid;
use Symfony\Component\HttpFoundation\Response;

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
        $stateId = $request->query->get('State', false);
        if ($stateId === false) {
            throw new Error\BadRequest('Missing required State query parameter.');
        }

        \SimpleSAML\Module\msverifiedid\Auth\Source\MicrosoftVerifiedId::resume($stateId);

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
        $stateId = $request->query->get('State', false);
        if ($stateId === false) {
            throw new Error\BadRequest('Missing required State query parameter.');
        }
        $opaqueId = $this->session->getData('string', 'opaqueId');
        $status = \SimpleSAML\Module\msverifiedid\Auth\Source\MicrosoftVerifiedId::handleStatusCheck($stateId, $opaqueId);
        switch($status) {
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
     */
    public function verify(Request $request): Template
    {
        $returnTo = $request->get('ReturnTo', false);
        if ($returnTo === false) {
            throw new Error\BadRequest('Missing required ReturnTo parameter.');
        }

        $httpUtils = new Utils\HTTP();
        $returnTo = $httpUtils->checkURLAllowed($returnTo);

        /**
         * What we do here is to extract the $state-array identifier, and check that it belongs to
         * the msverifiedid:Verify process.
         */
        if (!preg_match('@State=(.*)@', $returnTo, $matches)) {
            die('Invalid ReturnTo URL for this example.');
        }

        /**
         * The loadState-function will not return if the second parameter does not
         * match the parameter passed to saveState, so by now we know that we arrived here
         * through the msverifiedid:Verify authentication page.
         */
        $stateId = urldecode($matches[1]);

        // time to handle login response
        if ($request->isMethod('POST')) {
            if ($request->request->get('action', null) === 'STOP') {
                \SimpleSAML\Module\msverifiedid\Auth\Source\MicrosoftVerifiedId::handleStop($stateId);
            }

            $opaqueId = $this->session->getData('string', 'opaqueId');
            \SimpleSAML\Module\msverifiedid\Auth\Source\MicrosoftVerifiedId::handleLogin($stateId, $opaqueId, $returnTo);
        } else {
            // if we get this far, we need to show the verified ID presentation request page to the user
            $opaqueId = Uuid::uuid4()->toString();
            $this->session->setData('string', 'opaqueId', $opaqueId);
            $verifyUrl = \SimpleSAML\Module\msverifiedid\Auth\Source\MicrosoftVerifiedId::initVerifyRequest($stateId, $opaqueId);
            $statusUrl = Module::getModuleURL('msverifiedid/status', [
                'State' => $stateId,
            ]);

            $t = new Template($this->config, 'msverifiedid:verify.twig');
            $t->data['verify_url'] = $verifyUrl;
            $t->data['status_url'] = $statusUrl;
            $t->data['return_to_url'] = $returnTo;
            $t->setStatusCode(200);
            return $t;
        }
    }
}
