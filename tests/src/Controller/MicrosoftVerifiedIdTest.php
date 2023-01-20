<?php

namespace SimpleSAML\Test\Module\msverifiedid\Controller;

use PHPUnit\Framework\TestCase;
use ReflectionClass;
use SimpleSAML\Auth\State;
use SimpleSAML\Configuration;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Module\msverifiedid\Controller;
use SimpleSAML\Module\msverifiedid\MicrosoftVerifiedId\PresentationRequestHelper;
use SimpleSAML\Module\msverifiedid\MicrosoftVerifiedId\StateData;
use SimpleSAML\Session;
use SimpleSAML\Utils\HTTP;
use SimpleSAML\XHTML\Template;
use SimpleSAML\TestUtils\StateClearer;
use Symfony\Component\HttpFoundation\Request;
use CirrusIdentity\SSP\Test\InMemoryStore;

/**
 * Set of tests for the controllers in the "msverifiedid" module.
 *
 * @package SimpleSAML\Test
 */
class MicrosoftVerifiedIdTest extends TestCase
{
    /** @var \SimpleSAML\Configuration */
    protected Configuration $config;

    /** @var \SimpleSAML\Session */
    protected Session $session;

    /**
     * Set up for each test.
     */
    protected function setUp(): void
    {
        (new StateClearer())->clearSSPState();

        $this->config = Configuration::loadFromArray(
            [
                'module.enable' => ['msverifiedid' => true],
                'secretsalt' => 'abc123',
                'enable.saml20-idp' => true,
                'store.type' => '\CirrusIdentity\SSP\Test\InMemoryStore',
                'debug' => true,
                'logging.level' => Logger::DEBUG,
                'logging.handler' => 'errorlog',
                'auth.adminpassword' => 'secret',
                'tempdir' => sys_get_temp_dir(),
                'loggingdir'  => sys_get_temp_dir(),
            ]
        );

        Configuration::setPreLoadedConfig($this->config, 'config.php');

        $this->config = Configuration::getInstance();

        $authSourceConfig = Configuration::loadFromArray(
            [
                'msverifiedid-test' => [
                    'msverifiedid:MicrosoftVerifiedId',
                ],
            ]
        );

        Configuration::setPreLoadedConfig($authSourceConfig, 'authsources.php');

        $this->config = Configuration::getInstance();

        $moduleConfig = Configuration::loadFromArray(
            [
                'client_id' => 'good-client-id',
                'client_secret' => 'good-client-secret',
                'tenant_id' => 'good-tenant-id',
                'verifier_id' => 'did:web:www.athena-institute.net',
                'verifier_client_name' => 'Veriable Credential Expert Verifier',
                'verifiable_credential_type' => 'VerifiedCredentialExpert',
                'accepted_issuer_ids' => ['did:web:www.athena-institute.net'],
                'scope' => '3db474b9-6a0c-4840-96ac-1fceb342124f/.default',
                'verifier_request_purpose' => 'To verify status',
                'ms_api_base_url' => 'https://verifiedid.did.msidentity.com/v1.0/',
                'allow_revoked' => false,
                'validate_linked_domain' => true,
            ]
        );

        Configuration::setPreLoadedConfig($moduleConfig, 'module_msverifiedid.php');

        $this->session = $this->getSession();
    }

    protected function tearDown(): void
    {
        InMemoryStore::clearInternalState();
    }

    /**
     * Test controller verify() with valid config state
     */
    public function testVerifySuccess(): void
    {
        $t = $this->getValidVerifyUrl();

        $this->assertTrue($t->isSuccessful());
    }

    /**
     * Test controller verify() with invalid client ID
     */
    public function testVerifyFailBadClientId(): void
    {
        $_SERVER['REQUEST_URI'] = '/module.php/msverifiedid/verify';
        $request = Request::create(
            '/verify',
            'GET',
            [
                'StateId' => 'someStateId',
                'ReturnTo' => Request::create(
                    '/resume',
                    'GET',
                    [
                        'StateId' => 'someStateId',
                        'ReturnTo' => Module::getModuleURL('msverifiedid/resume', [
                            'StateId' => 'someStateId',
                        ])
                    ]
                )->getUri()
            ]
        );

        $c = new Controller\MicrosoftVerifiedId($this->config, $this->session);
        $c->setAuthState(new class () extends State {
            public static function loadState(string $id, string $stage, bool $allowMissing = false): ?array
            {
                return [
                    'msverifiedid:AuthID' => 'msverifiedid-test',
                ];
            }
        });

        $mockPresReqHelper = $this->createMock(PresentationRequestHelper::class);
        $mockPresReqHelper->method('initPresentationRequest')
            ->willThrowException(new \Exception('Get AAD access token failed'));

        $c->setPresReqHelper($mockPresReqHelper);

        $this->expectExceptionMessage('Get AAD access token failed');

        $c->verify($request);
    }

    /**
     * Test controller verify() with invalid verifier ID
     */
    public function testVerifyFailBadVerifierId(): void
    {
        $_SERVER['REQUEST_URI'] = '/module.php/msverifiedid/verify';
        $request = Request::create(
            '/verify',
            'GET',
            [
                'StateId' => 'someStateId',
                'ReturnTo' => Request::create(
                    '/resume',
                    'GET',
                    [
                        'StateId' => 'someStateId',
                        'ReturnTo' => Module::getModuleURL('msverifiedid/resume', [
                            'StateId' => 'someStateId',
                        ])
                    ]
                )->getUri()
            ]
        );

        $c = new Controller\MicrosoftVerifiedId($this->config, $this->session);
        $c->setAuthState(new class () extends State {
            public static function loadState(string $id, string $stage, bool $allowMissing = false): ?array
            {
                return [
                    'msverifiedid:AuthID' => 'msverifiedid-test',
                ];
            }
        });

        $mockPresReqHelper = $this->createMock(PresentationRequestHelper::class);
        $mockPresReqHelper->method('initPresentationRequest')
            ->willThrowException(new \Exception('VC presentation request failed'));

        $c->setPresReqHelper($mockPresReqHelper);

        $this->expectExceptionMessage('VC presentation request failed');

        $c->verify($request);
    }

    /**
     * Test controller status() response when VC presentation request QR code has not been
     * retrieved by client (via QR code scan or deep link click)
     */
    public function testStatusPending(): void
    {
        $this->getValidVerifyUrl();

        $_SERVER['REQUEST_URI'] = '/module.php/msverifiedid/status';
        $request = Request::create(
            '/status',
            'GET',
            [
                'StateId' => 'someStateId',
            ]
        );

        $c = new Controller\MicrosoftVerifiedId($this->config, $this->session);
        $c->setAuthState(new class () extends State {
            public static function loadState(string $id, string $stage, bool $allowMissing = false): ?array
            {
                return [
                    'msverifiedid:AuthID' => 'msverifiedid-test',
                ];
            }
        });

        $response = $c->status($request);
        $this->assertEquals(200, $response->getStatusCode());
    }

    /**
     * Test controller status() response when VC presentation request QR code has been
     * retrieved by client (via QR code scan or deep link click)
     */
    public function testStatusRetrieved(): void
    {
        $this->getValidVerifyUrl();

        $c = new Controller\MicrosoftVerifiedId($this->config, $this->session);
        $c->setAuthState(new class () extends State {
            public static function loadState(string $id, string $stage, bool $allowMissing = false): ?array
            {
                return [
                    'msverifiedid:AuthID' => 'msverifiedid-test',
                ];
            }
        });

        $_SERVER['REQUEST_URI'] = '/module.php/msverifiedid/callback';

        $request = Request::create(
            '/callback',
            'POST',
            [],
            [],
            [],
            [
                'CONTENT_TYPE' => 'application/json',
                'HTTP_api-key' => $this->session->getData('string', 'apiKey')
            ],
            json_encode(
                [
                    'requestId' => '8ef05a1b-1b28-4b7b-a2b8-ce455aa8d1bf',
                    'requestStatus' => 'request_retrieved',
                    'state' => $this->session->getData('string', 'opaqueId')
                ]
            )
        );

        $c->callback($request);

        $_SERVER['REQUEST_URI'] = '/module.php/msverifiedid/status';
        $request = Request::create(
            '/status',
            'GET',
            [
                'StateId' => 'someStateId',
            ]
        );

        $response = $c->status($request);

        $this->assertEquals(202, $response->getStatusCode());
    }

    /**
     * Test controller status() response when VC presentation request QR code has been
     * retrieved by client (via QR code scan or deep link click) AND client has shared
     * their VC
     */
    public function testStatusVerified(): void
    {
        $this->getValidVerifyUrl();

        $c = new Controller\MicrosoftVerifiedId($this->config, $this->session);
        $c->setAuthState(new class () extends State {
            public static function loadState(string $id, string $stage, bool $allowMissing = false): ?array
            {
                return [
                    'msverifiedid:AuthID' => 'msverifiedid-test',
                ];
            }
        });

        $_SERVER['REQUEST_URI'] = '/module.php/msverifiedid/callback';

        $request = Request::create(
            '/callback',
            'POST',
            [],
            [],
            [],
            [
                'CONTENT_TYPE' => 'application/json',
                'HTTP_api-key' => $this->session->getData('string', 'apiKey')
            ],
            json_encode(
                [
                    'requestId' => '8ef05a1b-1b28-4b7b-a2b8-ce455aa8d1bf',
                    'requestStatus' => 'request_retrieved',
                    'state' => $this->session->getData('string', 'opaqueId')
                ]
            )
        );

        $c->callback($request);

        $_SERVER['REQUEST_URI'] = '/module.php/msverifiedid/callback';

        $request = Request::create(
            '/callback',
            'POST',
            [],
            [],
            [],
            [
                'CONTENT_TYPE' => 'application/json',
                'HTTP_api-key' => $this->session->getData('string', 'apiKey')
            ],
            json_encode(
                [
                    'requestId' => 'fd117ac1-76c5-44fc-a36a-42f8c93fefd3',
                    'requestStatus' => 'presentation_verified',
                    'state' => $this->session->getData('string', 'opaqueId'),
                    'verifiedCredentialsData' => [
                        [
                            'issuer' => 'did:web:www.athena-institute.net',
                            'type' => [
                                'VerifiedCredentialExpert'
                            ],
                            'claims' => [
                                'firstName' => 'Foo',
                                'lastName' => 'Bar'
                            ],
                            'credentialState' => [
                                'revocationStatus' => 'VALID'
                            ],
                            'domainValidation' =>  [
                                'url' => 'https://www.athena-institute.net/'
                            ]
                        ]
                    ]
                ]
            )
        );

        $c->callback($request);

        $_SERVER['REQUEST_URI'] = '/module.php/msverifiedid/status';
        $request = Request::create(
            '/status',
            'GET',
            [
                'StateId' => 'someStateId',
            ]
        );

        $response = $c->status($request);

        $this->assertEquals(201, $response->getStatusCode());
    }

    /**
     * Test completion of login process once VC has been successfully
     * presented/verified.
     */
    public function testLoginCompletion(): void
    {
        $this->getValidVerifyUrl();

        $c = new Controller\MicrosoftVerifiedId($this->config, $this->session);
        $c->setAuthState(new class () extends State {
            public static function loadState(string $id, string $stage, bool $allowMissing = false): ?array
            {
                return [
                    'msverifiedid:AuthID' => 'msverifiedid-test',
                ];
            }
        });

        // first callback (VC presentation request retrieved)
        $_SERVER['REQUEST_URI'] = '/module.php/msverifiedid/callback';

        $request = Request::create(
            '/callback',
            'POST',
            [],
            [],
            [],
            [
                'CONTENT_TYPE' => 'application/json',
                'HTTP_api-key' => $this->session->getData('string', 'apiKey')
            ],
            json_encode(
                [
                    'requestId' => '8ef05a1b-1b28-4b7b-a2b8-ce455aa8d1bf',
                    'requestStatus' => 'request_retrieved',
                    'state' => $this->session->getData('string', 'opaqueId')
                ]
            )
        );

        $c->callback($request);

        // second callback (VC presented/verified)
        $_SERVER['REQUEST_URI'] = '/module.php/msverifiedid/callback';

        $request = Request::create(
            '/callback',
            'POST',
            [],
            [],
            [],
            [
                'CONTENT_TYPE' => 'application/json',
                'HTTP_api-key' => $this->session->getData('string', 'apiKey')
            ],
            json_encode(
                [
                    'requestId' => 'fd117ac1-76c5-44fc-a36a-42f8c93fefd3',
                    'requestStatus' => 'presentation_verified',
                    'state' => $this->session->getData('string', 'opaqueId'),
                    'verifiedCredentialsData' => [
                        [
                            'issuer' => 'did:web:www.athena-institute.net',
                            'type' => [
                                'VerifiedCredentialExpert'
                            ],
                            'claims' => [
                                'firstName' => 'Foo',
                                'lastName' => 'Bar'
                            ],
                            'credentialState' => [
                                'revocationStatus' => 'VALID'
                            ],
                            'domainValidation' =>  [
                                'url' => 'https://www.athena-institute.net/'
                            ]
                        ]
                    ]
                ]
            )
        );

        $c->callback($request);

        $expectedUrl = Module::getModuleURL('msverifiedid/resume', [
            'StateId' => 'someStateId',
        ]);
        $mockHttp = $this->createMock(HTTP::class);
        $mockHttp->method('redirectTrustedURL')
            ->with(
                $expectedUrl
            )
            ->willThrowException(new \Exception('Redirect expected'));

        // mock POSTing form to continue login process
        $_SERVER['REQUEST_URI'] = '/module.php/msverifiedid/verify';
        $request = Request::create(
            '/verify',
            'POST',
            [
                'StateId' => 'someStateId',
                'ReturnTo' => $expectedUrl
            ]
        );

        $c->setHttp($mockHttp);

        $this->expectExceptionMessage('Redirect expected');

        try {
            $c->verify($request);
        } finally {
            $this->assertSame(['firstName' => 'Foo', 'lastName' => 'Bar'], $this->session->getData('array', 'claims'));
        }
    }

    private function getValidVerifyUrl(): Template
    {
        $_SERVER['REQUEST_URI'] = '/module.php/msverifiedid/verify';
        $request = Request::create(
            '/verify',
            'GET',
            [
                'StateId' => 'someStateId',
                'ReturnTo' => Request::create(
                    '/resume',
                    'GET',
                    [
                        'StateId' => 'someStateId',
                        'ReturnTo' => Module::getModuleURL('msverifiedid/resume', [
                            'StateId' => 'someStateId',
                        ])
                    ]
                )->getUri()
            ]
        );

        $c = new Controller\MicrosoftVerifiedId($this->config, $this->session);
        $c->setAuthState(new class () extends State {
            public static function loadState(string $id, string $stage, bool $allowMissing = false): ?array
            {
                return [
                    'msverifiedid:AuthID' => 'msverifiedid-test',
                ];
            }
        });

        $mockPresReqHelper = $this->createMock(PresentationRequestHelper::class);
        // phpcs:disable
        $mockPresReqHelper->method('initPresentationRequest')
            ->willReturn('openid-vc://?request_uri=https://beta.did.msidentity.com/v1.0/tenants/5c8b71e9-6b28-4bfd-9bf5-c44c7883ac22/verifiableCredentials/presentationRequests/ae1f7d86-17f7-4152-a71e-468630b34d7f');
        // phpcs:enable

        $c->setPresReqHelper($mockPresReqHelper);

        return $c->verify($request);
    }

    private function getSession(): Session
    {
        $session = Session::getSessionFromRequest();
        //cli/phpunit sessions don't have session ids, but SessionHandlerStore needs a session id to save dirty state
        $class = new ReflectionClass(Session::class);
        $prop = $class->getProperty('sessionId');
        $prop->setAccessible(true);
        $prop->setValue($session, 'mockedSessionId');
        $this->assertEquals('mockedSessionId', $session->getSessionId());
        return $session;
    }
}
