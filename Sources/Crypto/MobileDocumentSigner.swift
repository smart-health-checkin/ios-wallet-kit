//
//  MobileDocumentSigner.swift
//  SMARTHealthCheckin
//

import CryptoKit
import Foundation

/// Builds the signed ISO 18013-5 `Document` the SMART Health Check-in profile asks the wallet to return (spec §8.4).
///
/// The wallet is its own issuer and its own device: both keys are created per response, the issuer key gets a
/// self-signed certificate in `x5chain`. The signatures make the mdoc complete and verifiable but say nothing about who
/// vouches for the content.
struct MobileDocumentSigner {
    
    let documentType: String
    let namespace: String
    
    /// How long the MSO stays valid.
    var validity: TimeInterval = 3600
    
    /// Returns the `Document` map holding a single issuer-signed element, `issuerAuth` and the detached device
    /// signature over `sessionTranscript`.
    func makeDocument(
        elementIdentifier: String,
        elementValue: String,
        sessionTranscript: CBOR,
        now: Date = Date()
    ) throws -> CBOR {
        let issuerKey = P256.Signing.PrivateKey()
        let deviceKey = P256.Signing.PrivateKey()
        
        // IssuerSignedItemBytes is hashed and placed in the response as the very same byte string
        let issuerSignedItem = Self.map([
            ("digestID", CBOR(unsignedInteger: 0)),
            ("random", CBOR(data: Data((0..<16).map { _ in UInt8.random(in: 0...UInt8.max) }))),
            ("elementIdentifier", CBOR(utf8String: elementIdentifier)),
            ("elementValue", CBOR(utf8String: elementValue))
        ])
        let issuerSignedItemBytes = issuerSignedItem.encodeToEmbeddedCBORData()
        guard let itemBytes = Data(issuerSignedItemBytes) else {
            throw MobileDocumentSignerError.cborEncodingFailure
        }
        let digest = Data(SHA256.hash(data: itemBytes))
        
        let issuerAuth = try makeIssuerAuth(
            issuerKey: issuerKey,
            deviceKey: deviceKey.publicKey,
            digest: digest,
            now: now
        )
        
        // Empty DeviceNameSpaces, the SMART response is always issuer-signed
        let deviceNameSpacesBytes = CBOR(dictionary: [:] as [CBOR: CBOR]).encodeToEmbeddedCBORData()
        let deviceSignature = try makeDeviceSignature(
            deviceKey: deviceKey,
            sessionTranscript: sessionTranscript,
            deviceNameSpacesBytes: deviceNameSpacesBytes
        )
        
        let nameSpaces = Self.map([(namespace, CBOR(array: [issuerSignedItemBytes]))])
        return Self.map([
            ("docType", CBOR(utf8String: documentType)),
            ("issuerSigned", Self.map([
                ("nameSpaces", nameSpaces),
                ("issuerAuth", issuerAuth)
            ])),
            ("deviceSigned", Self.map([
                ("nameSpaces", deviceNameSpacesBytes),
                ("deviceAuth", Self.map([("deviceSignature", deviceSignature)]))
            ]))
        ])
    }
    
    // MARK: - Issuer Auth
    
    private func makeIssuerAuth(
        issuerKey: P256.Signing.PrivateKey,
        deviceKey: P256.Signing.PublicKey,
        digest: Data,
        now: Date
    ) throws -> CBOR {
        let signed = Self.dateTime(now)
        let mso = Self.map([
            ("version", CBOR(utf8String: "1.0")),
            ("digestAlgorithm", CBOR(utf8String: "SHA-256")),
            ("valueDigests", Self.map([
                (namespace, CBOR(dictionary: [CBOR(unsignedInteger: 0): CBOR(data: digest)]))
            ])),
            ("deviceKeyInfo", Self.map([("deviceKey", Self.coseKey(deviceKey))])),
            ("docType", CBOR(utf8String: documentType)),
            ("validityInfo", Self.map([
                ("signed", signed),
                ("validFrom", signed),
                ("validUntil", Self.dateTime(now.addingTimeInterval(validity)))
            ]))
        ])
        guard let payload = Data(mso.encodeToEmbeddedCBORData()) else {
            throw MobileDocumentSignerError.cborEncodingFailure
        }
        
        let certificate = try SelfSignedCertificate.makeDER(
            commonName: "SMART Health Check-in Wallet",
            key: issuerKey,
            validFrom: now.addingTimeInterval(-300),
            validUntil: now.addingTimeInterval(validity + 300)
        )
        let x5chain = CBOR(dictionary: [CBOR(unsignedInteger: 33): CBOR(data: certificate)])
        return try Self.coseSign1(key: issuerKey, unprotected: x5chain, payload: payload, isDetached: false)
    }
    
    // MARK: - Device Signature
    
    private func makeDeviceSignature(
        deviceKey: P256.Signing.PrivateKey,
        sessionTranscript: CBOR,
        deviceNameSpacesBytes: CBOR
    ) throws -> CBOR {
        let deviceAuthentication = CBOR(array: [
            CBOR(utf8String: "DeviceAuthentication"),
            sessionTranscript,
            CBOR(utf8String: documentType),
            deviceNameSpacesBytes
        ])
        guard let payload = Data(deviceAuthentication.encodeToEmbeddedCBORData()) else {
            throw MobileDocumentSignerError.cborEncodingFailure
        }
        return try Self.coseSign1(
            key: deviceKey,
            unprotected: CBOR(dictionary: [:] as [CBOR: CBOR]),
            payload: payload,
            isDetached: true
        )
    }
    
    // MARK: - COSE
    
    /// COSE\_Sign1 with protected header `{1: -7}` (ES256) and an empty external AAD. For a detached signature the
    /// payload is signed but replaced by `null` in the structure.
    private static func coseSign1(
        key: P256.Signing.PrivateKey,
        unprotected: CBOR,
        payload: Data,
        isDetached: Bool
    ) throws -> CBOR {
        let protectedMap = CBOR(dictionary: [CBOR(unsignedInteger: 1): CBOR(integer: -7)])
        guard let protectedBytes = Data(protectedMap) else {
            throw MobileDocumentSignerError.cborEncodingFailure
        }
        let signatureStructure = CBOR(array: [
            CBOR(utf8String: "Signature1"),
            CBOR(data: protectedBytes),
            CBOR(data: Data()),
            CBOR(data: payload)
        ])
        guard let signedBytes = Data(signatureStructure) else {
            throw MobileDocumentSignerError.cborEncodingFailure
        }
        let signature = try key.signature(for: signedBytes)
        return CBOR(array: [
            CBOR(data: protectedBytes),
            unprotected,
            isDetached ? CBOR.cborNil() : CBOR(data: payload),
            CBOR(data: signature.rawRepresentation)
        ])
    }
    
    /// COSE\_Key for an EC2 P-256 public key.
    static func coseKey(_ publicKey: P256.Signing.PublicKey) -> CBOR {
        let point = publicKey.x963Representation
        let x = CBOR(data: point.subdata(in: 1..<33))
        let y = CBOR(data: point.subdata(in: 33..<65))
        let keys = [
            CBOR(unsignedInteger: 1),
            CBOR(integer: -1),
            CBOR(integer: -2),
            CBOR(integer: -3)
        ]
        return CBOR(dictionary: [
            keys[0]: CBOR(unsignedInteger: 2),
            keys[1]: CBOR(unsignedInteger: 1),
            keys[2]: x,
            keys[3]: y
        ], keyOrderList: keys)
    }
    
    // MARK: - Helpers
    
    /// Text-keyed map that encodes its entries in the given order.
    private static func map(_ entries: [(String, CBOR)]) -> CBOR {
        let keys = entries.map { CBOR(utf8String: $0.0) }
        var dictionary: [CBOR: CBOR] = [:]
        for (key, entry) in zip(keys, entries) {
            dictionary[key] = entry.1
        }
        return CBOR(dictionary: dictionary, keyOrderList: keys)
    }
    
    /// Tag 0 date-time in UTC without fractional seconds.
    private static func dateTime(_ date: Date) -> CBOR {
        CBOR(cbor: CBOR(utf8String: ISO8601DateFormatter().string(from: date)), tag: CBOR(unsignedInteger: 0))
    }
}

enum MobileDocumentSignerError: Error, LocalizedError {
    case cborEncodingFailure
    
    var errorDescription: String? {
        "Failed to encode the signed mdoc structures as CBOR."
    }
}
