<?php

namespace SimpleSAML\Module\msverifiedid\MicrosoftVerifiedId;

use SimpleSAML\Error;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use Ramsey\Uuid\Uuid;
use TheNetworg\OAuth2\Client\Provider\Azure;
use GuzzleHttp\Client;

class RestApiPresentationRequestHelper extends PresentationRequestHelper
{
    /**
     * Initiate request for Verified ID Presentation
     *
     * This function requests a new openid-vc URL and returns
     * the needed info to render the QR code or, on mobile platforms,
     * to open a deep link in Microsoft Authenticator.
     *
     * @return string url
     * @throws \SimpleSAML\Error\Exception
     */
    public function initPresentationRequest(): string
    {
        /* Get access token */
        $provider = new Azure([
            'clientId'                  => $this->stateData->clientId,
            'clientSecret'              => $this->stateData->clientSecret,
            'tenant'                    => $this->stateData->tenantId,
            'defaultEndPointVersion'    => Azure::ENDPOINT_VERSION_2_0
        ]);

        try {
            $token = $provider->getAccessToken(
                'client_credentials',
                ['scope' => $this->stateData->scope]
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
                'state' => $this->opaqueId,
                'headers' => [
                    'api-key' => $this->apiKey
                ]
            ],
            'authority' => $this->stateData->verifierId,
            'registration' => [
                'clientName' => $this->stateData->verifierClientName
            ],
            'includeReceipt' => false,
            'requestedCredentials' => [
                [
                    'type' => $this->stateData->verifiableCredentialType,
                    'acceptedIssuers' => $this->stateData->acceptedIssuerIds,
                    'configuration' => [
                        'validation' => [
                            'allowRevoked' => $this->stateData->allowRevoked,
                            'validateLinkedDomain' => true
                        ]
                    ]
                ]

            ]
        ];
        if ($this->stateData->verifierRequestPurpose !== null) {
            $verifyRequest['requestedCredentials'][0]['purpose'] = $this->stateData->verifierRequestPurpose;
        }

        Logger::debug("*** createPresentationRequest body: " . json_encode($verifyRequest, JSON_UNESCAPED_SLASHES));
        /* Setup request to send json via POST */
        $httpClient = new Client();
        $response = $httpClient->request(
            'POST',
            $this->stateData->msApiBaseUrl . 'verifiableCredentials/createPresentationRequest',
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
            Logger::debug("*** createPresentationRequest response: " . json_encode($respObj));
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