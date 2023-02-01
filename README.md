# Microsoft Entra Verified ID auth module

This module adds Microsoft Entra Verified ID as auth source to simpleSAMLphp.

## Disclaimer
This module was not created by Microsoft and will not be supported by them. Please use [github issues](https://github.com/windhamg/simplesamlphp-module-msverifiedid/issues/new) for any questions about this module.

## Credits
Development of this module would not have been possible without the wonderful documentation and API usage examples contributed by the developers of the [Active Directory Verifiable Credentials (Python) GitHub repo](https://github.com/Azure-Samples/active-directory-verifiable-credentials-python).

## Install

Install with composer

```bash
    composer require windhamg/simplesamlphp-module-msverifiedid
```

## Azure Setup for Verified ID credential verification

**Note**: This auth module only handles Microsoft Entra Verified ID credential verification. Credential issuance is out of scope for this project. You can learn more about Verified ID credential issuance [here](https://learn.microsoft.com/en-us/azure/active-directory/verifiable-credentials/verifiable-credentials-configure-issuer).

Before you can configure/use the `msverifiedid` auth module, you must perform the following steps:

1. If you don't already have one, [create an Azure tenant](https://azure.microsoft.com/free/?WT.mc_id=A261C142F) with an active subscription (can be a free account).
2. Follow [Microsoft's Verifiable Credentials Tenant Configuration documentation](https://learn.microsoft.com/en-us/azure/active-directory/verifiable-credentials/verifiable-credentials-configure-tenant) to create a key vault, set-up Verified ID, and register an application in Azure
   * When [registering the application in Azure](https://learn.microsoft.com/en-us/azure/active-directory/verifiable-credentials/verifiable-credentials-configure-tenant#register-an-application-in-azure-ad) follow these additional steps:
     - From the Certificates & secrets page, in the Client secrets section, choose `New client secret`
     - Type a key description (for instance "app secret").
     - Select a key duration.
     - When you press the Add button, the key value will be displayed, copy and save the value in a safe location.
     - You'll need this key later to configure the sample application. This key value **will not** be displayed again, nor retrievable by any other means, so record it as soon as it is visible from the Azure portal.
3. (Optional, if you will be verifying credentials that have already been defined -- e.g., by your organization or another). Create your credential by following the [instructions in the Azure portal](https://learn.microsoft.com/en-us/azure/active-directory/verifiable-credentials/verifiable-credentials-configure-issuer#create-the-verified-credential-expert-card-in-azure). You may substitute the JSON documents located in `config-templates/VerifiedCredentialExpertDisplay.json` and `config-templates/VerifiedCredentialExpertRules.json` for those in Microsoft's instructions, if you wish. Ultimately, you'll want to specify your own credential display template and rules, aligning with the verified credential(s) your organization issues.
   * While credential issuance is out-of-scope, you can find more details on the credential issuance REST API [here](https://learn.microsoft.com/en-us/azure/active-directory/verifiable-credentials/issuance-request-api).
4. Gather configuration details:
   * On the Azure AD app overview page in the Azure portal, go to ***Azure Active Directory > Manage > App Registrations > Owned Applications*** then click on the display name of the app.
   ![App Registration 1](README_files/azure-ad-app-registrations-1.png)
   * Record the values for `Application (client) ID` and `Directory (tenant) ID` (values obscured in screenshot below, but these will be v4 UUIDs).
   ![App Registration 2](README_files/azure-ad-app-registrations-2.png)
   * `Verifier ID`: this is the identifier, starting with `did:web:` (or, less commonly, `did:ion:`) that you established in step 2, above. This may be the same identifier as your issuing identifier (e.g., if you are verifying credentials issued by your own organization).
   ![Verifier ID](README_files/verified-id-org-settings.png)
   * `Verifier Credential Type`: this is the value specified in the issuer's credential rules definition (for example, `config-templates/VerifiedCredentialExpertRules.json`). It can be found in the **issuer's** Verified ID portal under ***Verified ID > Credentials > [Credential name]***
   ![Verifier Credential Type](README_files/verified-id-credential-settings.png)
   * `Accepted Issuer IDs`: these are the identifiers, starting with `did:web:` (or, less commonly, `did:ion:`), from which you will accept a verified ID. This might be the same value as the `Verifier ID` (if your organization both issues and verifies Verified IDs), or it might belong to another organization. More than one accepted issuer ID is permitted, as multiple orgnizations might issue verified IDs of the same type.

## Configuration

Ensure you are using something other than `phpsession` as the `store.type` value in `config.php` (e.g., `sql` or `memcache`). This is necessary due to the fact that Microsoft will make API callbacks to SSP, which are not tied to the user's SSP session.

Next thing you need to do is to enable the module: in `config.php`,
search for the `module.enable` key and set `authorize` to true:

```php
    'module.enable' => [
        'msverifiedid' => true,
        …
    ],
```

Add the authentication source to `authsource.php`:
```php
$config = [
...
    'msverifiedid' => [
        'msverifiedid:MicrosoftVerifiedId',
    ],
...
```
*Note*: If you wish to add a prefix to the attributes returned from the authentication source, you may do so by adding an `attributePrefix` property, e.g.:
```php
$config = [
...
    'msverifiedid' => [
        'msverifiedid:MicrosoftVerifiedId',
        'attributePrefix' => 'vc.'
    ],
...
```

Then you need to copy `config-templates/module_msverifiedid.php` to your config directory and adjust settings accordingly (using the values collected under `Gather configuration details` above). See the file for parameters description.

## Local testing

  1. Clone the `ssp2` branch from https://github.com/cirrusidentity/docker-simplesamlphp (clone into a separate directory outside this project):
     ```bash
     git clone --branch ssp2 --single-branch https://github.com/cirrusidentity/docker-simplesamlphp.git
     ```
  2. `cd` into the `docker-simplesamlphp` project directory.
  3. 
     ```bash
     cd docker-simplesamlphp/docker
     SSP_IMAGE_TAG=v2.0.0-rc2
     docker build -t cirrusid/simplesamlphp:$SSP_IMAGE_TAG -f Dockerfile .
     docker tag cirrusid/simplesamlphp:$SSP_IMAGE_TAG
     docker tag cirrusid/simplesamlphp:$SSP_IMAGE_TAG cirrusid/simplesamlphp:latest
     ```
  4. Now use [ngrok](https://ngrok.com/) to create a hosted HTTPS proxy for your local SSP instance. In a shell: `ngrok http https://localhost:8443`. Record the forwarding URL (e.g., `https://2c1c-69-137-176-246.ngrok.io`) for later.
  5. `cd` back into this project directory.
  6. Run the following command in a shell in the top-level of this project directory. Replace `https://2c1c-69-137-176-246.ngrok.io` with whatever ngrok returned for your forwarding URL in step 4, above. If your ngrok forwarding URL changes in the future, you can re-run this command to update it (just use the previous ngrok URL value instead of `https://your-forwarding-url.ngrok.io`).
     ```bash
     scripts/set-ngrok-url.sh https://your-forwarding-url.ngrok.io https://2c1c-69-137-176-246.ngrok.io
     ```
  7. Copy `config-templates/module_msverifiedid.php` to the `samples/idp` folder and edit, per the instructions in [Configuration](#configuration) above. A working sample file is not included for this particular file, as it requires a client ID/key from your Azure AD application.
  8. Run the following to launch the `docker-simplesamlphp` container, using the local `simplesamlphp-module-msverifiedid` module and configuration files from the `samples` directory:
     ```bash
     docker run --name ssp-idp \                                              
     --mount type=bind,source="$(pwd)/samples/cert",target=/var/simplesamlphp/cert,readonly \
     --mount type=bind,source="$(pwd)/samples/idp/authsources.php",target=/var/simplesamlphp/config/authsources.php,readonly \
     --mount type=bind,source="$(pwd)/samples/idp/config-override.php",target=/var/simplesamlphp/config/config-override.php,readonly \
     --mount type=bind,source="$(pwd)/samples/idp/saml20-idp-hosted.php",target=/var/simplesamlphp/metadata/saml20-idp-hosted.php,readonly \
     --mount type=bind,source="$(pwd)/samples/sp/saml20-idp-remote.php",target=/var/simplesamlphp/metadata/saml20-idp-remote.php,readonly \
     --mount type=bind,source="$(pwd)/samples/idp/saml20-sp-remote.php",target=/var/simplesamlphp/metadata/saml20-sp-remote.php,readonly \
     --mount type=bind,source="$(pwd)/samples/idp/module_msverifiedid.php",target=/var/simplesamlphp/config/module_msverifiedid.php,readonly \
     --mount type=bind,source="$(pwd)/samples/attributemap",target=/var/simplesamlphp/attributemap,readonly \
     --mount type=bind,source="$(pwd)",target=/var/simplesamlphp/staging-modules/msverifiedid,readonly \
     -e STAGINGCOMPOSERREPOS=msverifiedid \
     -e COMPOSER_REQUIRE="cirrusidentity/simplesamlphp-module-msverifiedid:dev-main" \
     -e SSP_ADMIN_PASSWORD=secret1 \
     -e SSP_SECRET_SALT=mysalt \
     -e SSP_APACHE_ALIAS=sample-idp/ \
     -p 8443:443 cirrusid/simplesamlphp:latest
     ```
  9.  In a browser do the following:
      - go to https://your-forwarding-url.ngrok.io/sample-idp/module.php/admin/test and login as `admin` with password `secret1` (or whatever you set `SSP_ADMIN_PASSWORD` to in step 8. above)
      - select the `default-sp` test link
      - you will be presented with a presentation request for your Microsoft verified credential. Scan the QR code with the MS Authenticator app on your mobile device (if using a mobile browser, you should be prompted to open the MS Authenticator app).
      - Click the "Share" button in the MS authenticator app to confirm release of your verified credential to the verifying party.
      - the SSP module will complete authentication, and the test IdP will return you back to the `default-sp`, which will display the attributes mapped from the verified credential claims