<?php

namespace SimpleSAML\Test\Module\msverifiedid\Auth\Source;

use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Error\CriticalConfigurationError;
use SimpleSAML\Logger;
use SimpleSAML\Module\msverifiedid\Auth\Source\MicrosoftVerifiedId;
use SimpleSAML\TestUtils\StateClearer;

class MicrosoftVerifiedIdTest extends TestCase
{
    /**
     * Set up for each test.
     */
    protected function setUp(): void
    {
        (new StateClearer())->clearSSPState();

        $config = Configuration::loadFromArray(
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
        Configuration::setPreLoadedConfig($config, 'config.php');

        $authSourceConfig = Configuration::loadFromArray(
            [
                'msverifiedid-test' => [
                    'msverifiedid:MicrosoftVerifiedId',
                ],
            ]
        );
        Configuration::setPreLoadedConfig($authSourceConfig, 'authsources.php');
    }

    public function missingPropertyProvider(): array
    {
        return [
            ['client_id'],
            ['client_secret'],
            ['tenant_id'],
            ['verifier_id'],
            ['verifier_client_name'],
            ['verifier_credential_type'],
            ['accepted_issuer_ids']
        ];
    }

    /**
     * @dataProvider missingPropertyProvider
     * @param string $property The config property to delete from module config
     */
    public function testMissingProperty(string $property): void
    {
        $configArray = $this->getModuleConfigArray();
        unset($configArray[$property]);
        $moduleConfig = Configuration::loadFromArray($configArray);

        Configuration::setPreLoadedConfig($moduleConfig, 'module_msverifiedid.php');

        $this->expectException(CriticalConfigurationError::class);

        new MicrosoftVerifiedId(['AuthId' => 'msverifiedid-test'], []);
    }

    private function getModuleConfigArray(): array
    {
        return [
            'client_id' => 'good-client-id',
            'client_secret' => 'good-client-secret',
            'tenant_id' => 'good-tenant-id',
            'verifier_id' => 'did:web:www.athena-institute.net',
            'verifier_client_name' => 'Veriable Credential Expert Verifier',
            'verifier_credential_type' => 'VerifiedCredentialExpert',
            'accepted_issuer_ids' => ['did:web:www.athena-institute.net'],
            'scope' => '3db474b9-6a0c-4840-96ac-1fceb342124f/.default',
            'verifier_request_purpose' => 'To verify status',
            'ms_api_base_url' => 'https://verifiedid.did.msidentity.com/v1.0/',
            'allow_revoked' => false,
            'validate_linked_domain' => true,
        ];
    }
}
