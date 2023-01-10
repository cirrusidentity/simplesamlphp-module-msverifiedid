<?php

namespace SimpleSAML\Module\msverifiedid\MicrosoftVerifiedId;

use SimpleSAML\Error;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use TheNetworg\OAuth2\Client\Provider\Azure;
use GuzzleHttp\Client;

class PresentationRequestHelper
{
    /**
     * Initiate request for Verified ID Presentation
     * @param \SimpleSAML\Module\msverifiedid\MicrosoftVerifiedId\StateData $stateData
     * @param string $opaqueId
     * @param string $apiKey
     * @return string url
     * @throws \SimpleSAML\Error\Exception
     */
    public function initPresentationRequest(
        StateData $stateData,
        string $opaqueId,
        string $apiKey
    ): string
    {
        /* Get access token */
        $provider = new Azure([
            'clientId'                  => $stateData->clientId,
            'clientSecret'              => $stateData->clientSecret,
            'tenant'                    => $stateData->tenantId,
            'defaultEndPointVersion'    => Azure::ENDPOINT_VERSION_2_0
        ]);

        try {
            $token = $provider->getAccessToken(
                'client_credentials',
                ['scope' => $stateData->scope]
            )->getToken();
            Logger::debug("*** token = $token");
        } catch (\Exception $e) {
            throw new Error\Exception('Get AAD access token failed: ' . $e->getMessage());
        }

        /* Build verify request */
        $verifyRequest = [
            'includeQRCode' => false,
            'callback' => [
                'url' => Module::getModuleURL('msverifiedid/callback'),
                'state' => $opaqueId,
                'headers' => [
                    'api-key' => $apiKey
                ]
            ],
            'authority' => $stateData->verifierId,
            'registration' => [
                'clientName' => $stateData->verifierClientName
            ],
            'includeReceipt' => false,
            'requestedCredentials' => [
                [
                    'type' => $stateData->verifiableCredentialType,
                    'acceptedIssuers' => $stateData->acceptedIssuerIds,
                    'configuration' => [
                        'validation' => [
                            'allowRevoked' => $stateData->allowRevoked,
                            'validateLinkedDomain' => true
                        ]
                    ]
                ]

            ]
        ];
        if ($stateData->verifierRequestPurpose !== null) {
            $verifyRequest['requestedCredentials'][0]['purpose'] = $stateData->verifierRequestPurpose;
        }

        Logger::debug("*** createPresentationRequest body: " . json_encode($verifyRequest, JSON_UNESCAPED_SLASHES));
        /* Setup request to send json via POST */
        $httpClient = new Client();
        $response = $httpClient->request(
            'POST',
            $stateData->msApiBaseUrl . 'verifiableCredentials/createPresentationRequest',
            [
                'http_errors' => false,
                'headers' => [
                    'Authorization' => 'Bearer ' . $token,
                    'Content-Type' => 'application/json'
                ],
                'body' => json_encode($verifyRequest, JSON_UNESCAPED_SLASHES)
            ]
        );
        if ($response->getStatusCode() === 201) {
            // return MS Authenticator URL from response
            $respObj = json_decode($response->getBody()->__toString());
            Logger::info("*** createPresentationRequest response: " . json_encode($respObj));
            return $respObj->url;
        }

        /* throw exception since verify request failed */
        Logger::error(
            "VC presentation request failed : code = {$response->getStatusCode()},
            body = {$response->getBody()->getContents()}"
        );
        throw new Error\Exception('VC presentation request failed');
    }
}