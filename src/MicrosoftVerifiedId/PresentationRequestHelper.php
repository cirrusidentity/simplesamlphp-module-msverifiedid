<?php

namespace SimpleSAML\Module\msverifiedid\MicrosoftVerifiedId;

abstract class PresentationRequestHelper
{
    /**
     * Config data for generating VC presentation request
     *
     * @var SimpleSAML\Module\msverifiedid\MicrosoftVerifiedId\StateData
     */
    protected StateData $stateData;

    /**
     * Opaque identifier used to identify the VC presentation request
     *
     * @var string
     */
    protected string $opaqueId;

    /**
     * API key passed in the VC presentation request, used to authorize
     * callbacks
     *
     * @var string
     */
    protected string $apiKey;

    /**
     * Initialize the presentation request helper object.
     *
     * @param SimpleSAML\Module\msverifiedid\MicrosoftVerifiedId\StateData $stateData  config data for generating VC presentation request
     * @param string $opaqueId        identifier used to identify the VC presentation request
     */
    public function __construct(
        StateData $stateData,
        string $opaqueId,
        string $apiKey
    ) {
        $this->stateData = $stateData;
        $this->opaqueId = $opaqueId;
        $this->apiKey = $apiKey;
    }

    /**
     * Initiate request for Verified ID Presentation
     *
     * @return string url
     * @throws \SimpleSAML\Error\Exception
     */
    abstract public function initPresentationRequest(): string;
}
