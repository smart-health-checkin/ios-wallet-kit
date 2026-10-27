# SMARTHealthCheckin

Wallet-side implementation of the `org.smarthealthit.checkin.1` credential from the
[SMART Health Check-in 1.0](https://smart-health-checkin.org/spec/). A verifier (for example a
clinic's web page) asks for health data through the [W3C Digital Credentials API](https://w3c-fedid.github.io/digital-credentials/),
and the wallet answers with an encrypted ISO 18013-5 mobile document.

The framework handles the protocol and nothing else. It validates the incoming request, gives you the verifier's
questions as a typed structure, and turns your answers into the signed and encrypted response the platform expects.
It has no UI, no data store and no FHIR model dependency. Bring your own FHIR library; any `Encodable` resource works.

## Dependencies

- `CryptoKit` (ships with iOS)
- `IdentityDocumentServices` (ships with iOS)
- `swift-certificates` package for `X509` and `SwiftASN1`

The framework contains a minimal implementation of `CBOR` in Swift, please substitute a real CBOR library for production
use.

## Usage

The framework is meant to be driven from an `IdentityDocumentProvider` extension (`IdentityDocumentServices`). In order
to get at the data bits that contain the SMART Health Check-in request, we need to look at the raw request, which is
only available from within `sendResponse()`. Since `sendResponse()` should only be called on user action, we should
first present the user with basic information about the request and let them "Proceed" to view the request. Under the
hood this calls `context.sendResponse()` and suspends while the user fulfills the request. See further down for one way
this can be achieved.

**1. Validate the request.** Pass the raw request to the session. This throws where the spec says the wallet must not
respond, and collects softer problems in `warnings`.

```swift
try await context.sendResponse { rawRequest in

    // S
    let session = try SMARTHealthCheckinSession(
        requestData: rawRequest.requestData,
        origin: context.requestingWebsiteOrigin
    )
    
    // Steps 2 to 4
}
```

**2. Read what is asked.** `session.smartRequest` is a `SMARTHealthCheckinRequest`: a purpose, the accepted FHIR
versions and a list of items. Each item has an `id`, a `title`, whether it is `required`, the media types it `accept`s
and a `content` selector, either `.selectionFHIR` (existing resources by profile or resource type) or `.formFHIR`
(complete a questionnaire). Unknown selector kinds arrive as `.extensionKind` so they can be answered as unsupported.

**3. Answer every item.** Show the request to the person, then build a `SMARTHealthCheckinResponse` with one status per
item and the artifacts that fulfill them.

```swift
let coverage = try SMARTHealthArtifact.fhirResource(myCoverage, id: "art-1", fulfills: ["item-coverage"])
let card = SMARTHealthArtifact.smartHealthCard(id: "art-2", fulfills: ["item-card"], verifiableCredential: [jws])

let response = SMARTHealthCheckinResponse(
    requestId: session.smartRequest.id,
    artifacts: [coverage, card],
    requestStatus: [
        SMARTHealthRequestItemStatus(item: "item-coverage", status: .fulfilled),
        SMARTHealthRequestItemStatus(item: "item-card", status: .fulfilled),
        SMARTHealthRequestItemStatus(item: "item-notes", status: .declined)
    ]
)
```

The only data the framework needs from the app is:

- FHIR resources as JSON, either any `Encodable` (`SMARTHealthArtifact.fhirResource(_:id:fulfills:)`) or serialized
  bytes (`SMARTHealthArtifact.fhirJSON(_:id:fulfills:)`), plus the FHIR version.
- SMART Health Card JWS strings (`.smartHealthCard`).
- A status per request item, with an optional message.

**4. Send it.** The session signs the response as an mdoc and encrypts it to the verifier. Return the result from the
`sendResponse` closure.

```swift
let responseData = try await session.encryptedResponse(for: response, in: context.request)
return ISO18013MobileDocumentResponse(responseData: responseData)
```

Since `sendResponse` has to be running while the person decides, the closure will usually suspend until the UI delivers
the response. Here's one example how a user's press on "Proceed" to view the request could be implemented:

```swift
let context: ISO18013MobileDocumentRequestContext

private func proceed() {
    Task {
        await runSendResponse()
    }
}

/// Wraps `sendResponse` to acquire `rawRequest`, validate the SMART JSON, then suspend until the user-driven UI feeds
/// back a `SMARTHealthCheckinResponse` via the continuation.
private func runSendResponse() async {
    do {
        try await context.sendResponse { rawRequest in
            let session: SMARTHealthCheckinSession
            do {
                session = try SMARTHealthCheckinSession(
                    requestData: rawRequest.requestData,
                    origin: context.requestingWebsiteOrigin
                )
            } catch {
                await MainActor.run { self.loadError = error.localizedDescription }
                throw error
            }
    
            await MainActor.run { self.smartRequest = session.smartRequest }
    
            let response: SMARTHealthCheckinResponse = try await withCheckedThrowingContinuation { continuation in
                Task { @MainActor in
                    self.responseContinuation = continuation
                }
            }
    
            let encryptedResponse = try await session.encryptedResponse(for: response, in: context.request)
    
            return ISO18013MobileDocumentResponse(responseData: encryptedResponse)
        }
    } catch {
        // sendResponse threw — likely cancellation or our own throw. Should probably surface to the UI.
    }
}
```

## Layout

| Folder | Contents |
|---|---|
| `CheckIn/` | The check-in types (`SMARTHealthCheckinRequest`, `SMARTHealthCheckinResponse`, `SMARTHealthArtifact`, `JSONValue`), request validation, the `DeviceRequest` parser, the mdoc credential and `SMARTHealthCheckinSession`. |
| `Crypto/` | HPKE response encryption, the mdoc signer and the self-signed certificate it uses. |
| `StandIns/` | Minimal CBOR implementation. |


## Technical details

### Request

The DC API hands the extension a JSON envelope `{"deviceRequest": "<base64url>", "encryptionInfo": "<base64url>"}`
(`IdentityDocumentWebPresentmentRawRequest.requestData`). The `deviceRequest` is an ISO 18013-5 `DeviceRequest` with a
`DocRequest` of type `org.smarthealthit.checkin.1`. The SMART JSON request travels as a string in
`ItemsRequest.requestInfo["org.smarthealthit.checkin.request"]`; the outer `nameSpaces` only advertise the
`smart_health_checkin_response` element.

`SMARTHealthCheckinRequestValidator` implements the wallet request steps WRQ-2 to WRQ-9 of the spec (§8.4). A malformed
envelope, a missing document type or request carrier, an invalid SMART request (wrong type or version, duplicate item
ids) or missing encryption info throws. Everything else, such as an unexpected `DeviceRequest` version, becomes a
warning. Reader authentication is never verified.

### Response

The response is a `SMARTHealthCheckinResponse` JSON document with `artifacts[]` and a `requestStatus[]` entry for each
request item. Artifacts are keyed by media type: `application/fhir+json` (raw FHIR JSON plus `fhirVersion`),
`application/smart-health-card` (`verifiableCredential` array of JWS strings), and a pass-through bucket for anything
else. Status codes are `fulfilled`, `partial`, `unavailable`, `declined`, `unsupported` and `error`. See the spec for
the exact rules, notably that every `artifacts[].fulfills` entry must reference a request item id.

The JSON is placed as a single string element (`smart_health_checkin_response`) in the `org.smarthealthit.checkin`
namespace of an ISO 18013-5 `Document`.

### Signing

The spec lets the wallet sign its own document, so `MobileDocumentSigner` creates a fresh P-256 issuer key and device
key for every response. `issuerAuth` is a COSE_Sign1 over a Mobile Security Object, with the digest of the response
element and the device key, and a throwaway self-signed certificate in `x5chain`. `deviceSignature` covers
`DeviceAuthentication` with the session transcript. The signatures make the mdoc well-formed and verifiable; they say
nothing about who vouches for the content, and no trust is attached to the certificate.

### Encryption

`HPKEResponseEncryption` implements the baseline suite required by the spec: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256,
AES-128-GCM, with the SessionTranscript as `info` and empty AAD. The SessionTranscript follows ISO 18013-7 for the DC
API: `[null, null, ["dcapi", SHA-256(CBOR([encryptionInfoBase64URL, origin]))]]`. The unpadded base64url string of
`encryptionInfo` is used exactly as received, because re-encoding breaks the transcript. The result is the raw CBOR of
`["dcapi", {"enc", "cipherText"}]`; `ISO18013MobileDocumentResponse` does the outer base64url encoding. Only
`kty=EC2` / `crv=P-256` recipient keys are accepted, and the framework never produces an unencrypted response.

### Relevant Specs

- [SMART Health Check-in 1.0](https://smart-health-checkin.org/spec/) for the request and response
  formats, the wallet request checks and the HPKE suite.
- [ISO/IEC 18013-5](https://www.iso.org/standard/69084.html) for the mdoc structures.
- [ISO/IEC 18013-7](https://www.iso.org/standard/82772.html) for the `org-iso-mdoc` DC API protocol.
