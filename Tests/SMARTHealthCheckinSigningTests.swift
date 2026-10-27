//
//  SMARTHealthCheckinSigningTests.swift
//  SMARTHealthCheckinTests
//

import CryptoKit
import Foundation
import Security
import Testing
@testable import SMARTHealthCheckin

struct MobileDocumentSignerTests {

    private static let documentType = "org.smarthealthit.checkin.1"
    private static let namespace = "org.smarthealthit.checkin"
    private static let element = "smart_health_checkin_response"

    @Test func signedDocumentVerifies() throws {
        let transcript = try HPKEResponseEncryption.sessionTranscript(
            encryptionInfoBase64URL: "encryption-info",
            origin: "https://clinic.example"
        )
        let signer = MobileDocumentSigner(documentType: Self.documentType, namespace: Self.namespace)
        let document = try signer.makeDocument(
            elementIdentifier: Self.element,
            elementValue: "{\"type\":\"smart-health-checkin-response\"}",
            sessionTranscript: transcript
        )

        let issuerSigned = try #require(document.dictionary?[CBOR(utf8String: "issuerSigned")]?.dictionary)
        let itemBytes = try #require(
            issuerSigned[CBOR(utf8String: "nameSpaces")]?.dictionary?[CBOR(utf8String: Self.namespace)]?.array?.first
        )
        let issuerAuth = try #require(issuerSigned[CBOR(utf8String: "issuerAuth")]?.array)
        #expect(issuerAuth.count == 4)

        // issuerAuth verifies with the certificate in x5chain
        let unprotected = try #require(issuerAuth[1].dictionary)
        let certificate = try #require(unprotected[CBOR(unsignedInteger: 33)]?.data)
        let issuerKey = try Self.publicKey(ofCertificate: certificate)
        let msoPayload = try #require(issuerAuth[2].data)
        #expect(try Self.verify(issuerAuth, payload: msoPayload, key: issuerKey))

        // The MSO digest matches the issuer-signed item as sent, and names the device key
        let msoBytes = try #require(CBOR.decode(from: msoPayload)?.data)
        let mso = try #require(CBOR.decode(from: msoBytes)?.dictionary)
        let digests = try #require(
            mso[CBOR(utf8String: "valueDigests")]?.dictionary?[CBOR(utf8String: Self.namespace)]?.dictionary
        )
        let expectedDigest = Data(SHA256.hash(data: try #require(Data(itemBytes))))
        #expect(digests[CBOR(unsignedInteger: 0)]?.data == expectedDigest)
        #expect(mso[CBOR(utf8String: "docType")]?.string == Self.documentType)

        let validity = try #require(mso[CBOR(utf8String: "validityInfo")]?.dictionary)
        for key in ["signed", "validFrom", "validUntil"] {
            let value = try #require(validity[CBOR(utf8String: key)]?.string)
            #expect(value.hasSuffix("Z") && !value.contains("."))
        }

        // The detached device signature covers DeviceAuthentication for this transcript
        let deviceKeyCOSE = try #require(
            mso[CBOR(utf8String: "deviceKeyInfo")]?.dictionary?[CBOR(utf8String: "deviceKey")]?.dictionary
        )
        let x = try #require(deviceKeyCOSE[CBOR(integer: -2)]?.data)
        let y = try #require(deviceKeyCOSE[CBOR(integer: -3)]?.data)
        let deviceKey = try P256.Signing.PublicKey(x963Representation: Data([4]) + x + y)

        let deviceSigned = try #require(document.dictionary?[CBOR(utf8String: "deviceSigned")]?.dictionary)
        let deviceNameSpacesBytes = try #require(deviceSigned[CBOR(utf8String: "nameSpaces")])
        let deviceSignature = try #require(
            deviceSigned[CBOR(utf8String: "deviceAuth")]?.dictionary?[CBOR(utf8String: "deviceSignature")]?.array
        )
        #expect(deviceSignature[2] == CBOR.cborNil())
        let deviceAuthentication = CBOR(array: [
            CBOR(utf8String: "DeviceAuthentication"),
            transcript,
            CBOR(utf8String: Self.documentType),
            deviceNameSpacesBytes
        ])
        let deviceAuthenticationBytes = try #require(Data(deviceAuthentication.encodeToEmbeddedCBORData()))
        #expect(try Self.verify(deviceSignature, payload: deviceAuthenticationBytes, key: deviceKey))
    }

    @Test func certificateIsParsableAndSelfSigned() throws {
        let key = P256.Signing.PrivateKey()
        let der = try SelfSignedCertificate.makeDER(
            commonName: "Test",
            key: key,
            validFrom: Date().addingTimeInterval(-60),
            validUntil: Date().addingTimeInterval(60)
        )
        let publicKey = try Self.publicKey(ofCertificate: der)
        #expect(publicKey.x963Representation == key.publicKey.x963Representation)
    }

    // MARK: - Helpers

    private static func publicKey(ofCertificate der: Data) throws -> P256.Signing.PublicKey {
        let certificate = try #require(SecCertificateCreateWithData(nil, der as CFData))
        let secKey = try #require(SecCertificateCopyKey(certificate))
        let external = try #require(SecKeyCopyExternalRepresentation(secKey, nil) as Data?)
        return try P256.Signing.PublicKey(x963Representation: external)
    }

    /// Checks a COSE_Sign1 with an empty external AAD against the given payload.
    private static func verify(_ sign1: [CBOR], payload: Data, key: P256.Signing.PublicKey) throws -> Bool {
        let protectedBytes = try #require(sign1[0].data)
        let signatureBytes = try #require(sign1[3].data)
        let structure = CBOR(array: [
            CBOR(utf8String: "Signature1"),
            CBOR(data: protectedBytes),
            CBOR(data: Data()),
            CBOR(data: payload)
        ])
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: signatureBytes)
        return key.isValidSignature(signature, for: try #require(Data(structure)))
    }
}

struct SMARTHealthCheckinRequestValidatorTests {

    private static let origin = URL(string: "https://clinic.example")
    private static let requestJSON = """
        {"type":"smart-health-checkin-request","version":"1","id":"r1","items":[
        {"id":"patient","title":"Patient","content":{"kind":"selection.fhir","resourceTypes":["Patient"]},
        "accept":["application/fhir+json"]}]}
        """

    @Test func validRequestPassesWithoutWarnings() throws {
        let data = try Self.requestData()
        let validated = try SMARTHealthCheckinRequestValidator.validate(requestData: data, origin: Self.origin)
        #expect(validated.smartRequest.id == "r1")
        #expect(validated.warnings.isEmpty)
    }

    @Test func missingOriginFails() throws {
        let data = try Self.requestData()
        #expect(throws: HPKEResponseEncryptionError.self) {
            try SMARTHealthCheckinRequestValidator.validate(requestData: data, origin: nil)
        }
    }

    @Test func otherDocumentTypeFails() throws {
        let data = try Self.requestData(documentType: "org.example.other")
        #expect(throws: SMARTHealthCheckinCredentialError.self) {
            try SMARTHealthCheckinRequestValidator.validate(requestData: data, origin: Self.origin)
        }
    }

    @Test func missingRequestTextFails() throws {
        let data = try Self.requestData(requestText: nil)
        #expect(throws: SMARTHealthCheckinCredentialError.self) {
            try SMARTHealthCheckinRequestValidator.validate(requestData: data, origin: Self.origin)
        }
    }

    @Test func missingEncryptionInfoFails() throws {
        let data = try Self.requestData(includeEncryptionInfo: false)
        #expect(throws: HPKEResponseEncryptionError.self) {
            try SMARTHealthCheckinRequestValidator.validate(requestData: data, origin: Self.origin)
        }
    }

    @Test func missingNonceOnlyWarns() throws {
        let data = try Self.requestData(includeNonce: false)
        let validated = try SMARTHealthCheckinRequestValidator.validate(requestData: data, origin: Self.origin)
        #expect(validated.warnings.count == 1)
    }

    @Test func duplicateItemIDsFail() throws {
        let json = Self.requestJSON.replacingOccurrences(
            of: "\"accept\":[\"application/fhir+json\"]}]}",
            with: "\"accept\":[\"application/fhir+json\"]},"
                + "{\"id\":\"patient\",\"title\":\"Again\",\"content\":{\"kind\":\"selection.fhir\"},\"accept\":[]}]}"
        )
        #expect(throws: SMARTHealthCheckinCredentialError.self) {
            try SMARTHealthCheckinRequestValidator.validateSMARTRequest(json)
        }
    }

    @Test func wrongTypeFails() {
        let json = Self.requestJSON.replacingOccurrences(of: "smart-health-checkin-request", with: "other")
        #expect(throws: SMARTHealthCheckinCredentialError.self) {
            try SMARTHealthCheckinRequestValidator.validateSMARTRequest(json)
        }
    }

    @Test func mistypedSelectorMembersOnlyAffectTheItem() throws {
        let json = Self.requestJSON.replacingOccurrences(of: "[\"Patient\"]", with: "\"Patient\"")
        let request = try SMARTHealthCheckinRequestValidator.validateSMARTRequest(json)
        guard case .extensionKind = request.items[0].content else {
            Issue.record("A mistyped selector should become an unsupported item.")
            return
        }
    }

    @Test func selectionWithFormMembersIsUnsupported() throws {
        let json = Self.requestJSON.replacingOccurrences(
            of: "\"resourceTypes\":[\"Patient\"]",
            with: "\"questionnaireCanonical\":\"https://example.org/q\""
        )
        let request = try SMARTHealthCheckinRequestValidator.validateSMARTRequest(json)
        guard case .extensionKind = request.items[0].content else {
            Issue.record("A selection with form members should become an unsupported item.")
            return
        }
    }

    // MARK: - Request Construction

    private static func requestData(
        documentType: String = "org.smarthealthit.checkin.1",
        requestText: String? = requestJSON,
        includeEncryptionInfo: Bool = true,
        includeNonce: Bool = true
    ) throws -> Data {
        var requestInfo: [CBOR: CBOR] = [:]
        if let requestText {
            requestInfo[CBOR(utf8String: "org.smarthealthit.checkin.request")] = CBOR(utf8String: requestText)
        }
        let itemsRequest = CBOR(dictionary: [
            CBOR(utf8String: "docType"): CBOR(utf8String: documentType),
            CBOR(utf8String: "nameSpaces"): CBOR(dictionary: [
                CBOR(utf8String: "org.smarthealthit.checkin"): CBOR(dictionary: [
                    CBOR(utf8String: "smart_health_checkin_response"): CBOR.cborFalse()
                ])
            ]),
            CBOR(utf8String: "requestInfo"): CBOR(dictionary: requestInfo)
        ])
        let deviceRequest = CBOR(dictionary: [
            CBOR(utf8String: "version"): CBOR(utf8String: "1.0"),
            CBOR(utf8String: "docRequests"): CBOR(array: [
                CBOR(dictionary: [CBOR(utf8String: "itemsRequest"): itemsRequest.encodeToEmbeddedCBORData()])
            ])
        ])

        var envelope = ["deviceRequest": base64URL(try #require(Data(deviceRequest)))]
        if includeEncryptionInfo {
            var parameters: [CBOR: CBOR] = [
                CBOR(utf8String: "recipientPublicKey"): MobileDocumentSigner.coseKey(P256.Signing.PrivateKey().publicKey)
            ]
            if includeNonce {
                parameters[CBOR(utf8String: "nonce")] = CBOR(data: Data(repeating: 7, count: 16))
            }
            let encryptionInfo = CBOR(array: [CBOR(utf8String: "dcapi"), CBOR(dictionary: parameters)])
            envelope["encryptionInfo"] = base64URL(try #require(Data(encryptionInfo)))
        }
        return try JSONEncoder().encode(envelope)
    }

    private static func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
