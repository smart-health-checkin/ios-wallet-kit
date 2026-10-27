//
//  HPKEResponseEncryption.swift
//  SMARTHealthCheckin
//

import CryptoKit
import Foundation
import IdentityDocumentServices
import os

/// Shared HPKE response encryption for the DC API `org-iso-mdoc` flow used by SMART Health Check-In.
///
/// Implements the baseline HPKE suite: DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM, with an `info` binding of
/// the SessionTranscript bytes and empty AAD.
///
/// ## Wire format
///
/// Input: the `IdentityDocumentWebPresentmentRawRequest.requestData` is the ISO 18013-7 JSON envelope
///        `{"deviceRequest": "<base64url CBOR>", "encryptionInfo": "<base64url CBOR>"}`. The exact unpadded base64url
///        form of `encryptionInfo` is captured verbatim — it is an input to the SessionTranscript and must be reused
///        without round-tripping.
///
/// Output: CBOR-encoded `dcapiResponse = ["dcapi", {"enc": bstr, "cipherText": bstr}]`.
///
/// ## Encoding convention for `ISO18013MobileDocumentResponse(responseData:)`
///
/// The returned bytes are the **raw CBOR encoding** of `dcapiResponse`, not a base64url-encoded UTF-8 string. The
/// `ISO18013MobileDocumentResponse(responseData:)` framework type handles base64url encoding of the outer DC API
/// transport.
public enum HPKEResponseEncryption {
    
    /// Parsed `["dcapi", { nonce, recipientPublicKey }]` from the incoming request envelope.
    public struct EncryptionInfo: Sendable {
        
        /// Per-session verifier nonce. Surfaced for completeness; not used by HPKE but present in the protocol envelope.
        public let nonce: Data
        
        /// Decoded recipient P-256 public key.
        public let recipientPublicKey: P256.KeyAgreement.PublicKey
        
        /// Exact unpadded base64url string as it arrived from the DC API — used verbatim in the SessionTranscript
        /// computation so the verifier can reproduce identical input bytes.
        public let rawBase64URL: String
    }
    
    /// Extracts the `encryptionInfo` CBOR from the ISO 18013-7 JSON envelope contained in
    /// `IdentityDocumentWebPresentmentRawRequest.requestData`.
    ///
    /// - Returns: the parsed `EncryptionInfo`, or `nil` if `requestData` is not the JSON envelope form (for example,
    ///            a raw CBOR DeviceRequest shipped in tests or ISO 18013-5 non-DC wire fixtures). Callers may then skip
    ///            encryption and fall back to plaintext responses.
    public static func extractEncryptionInfo(from requestData: Data) throws -> EncryptionInfo? {
        guard
            let json = try? JSONSerialization.jsonObject(with: requestData) as? [String: Any],
            let encInfoBase64 = json["encryptionInfo"] as? String
        else {
            return nil
        }
        guard let cborBytes = base64URLDecode(encInfoBase64) else {
            throw HPKEResponseEncryptionError.invalidEncryptionInfoCBOR
        }
        guard
            let root = CBOR.decode(from: cborBytes),
            let array = root.array,
            array.count >= 2,
            array[0].string == "dcapi",
            let params = array[1].dictionary,
            let keyCBOR = params[CBOR(utf8String: "recipientPublicKey")]
        else {
            throw HPKEResponseEncryptionError.invalidEncryptionInfoCBOR
        }
        let recipientPublicKey = try parseCOSEP256PublicKey(keyCBOR)
        
        // A missing nonce is not fatal, the spec only asks receivers to warn about it.
        let nonce = params[CBOR(utf8String: "nonce")]?.data ?? Data()
        return EncryptionInfo(
            nonce: nonce,
            recipientPublicKey: recipientPublicKey,
            rawBase64URL: encInfoBase64
        )
    }
    
    /// Builds the SessionTranscript bytes per spec §8.3:
    /// `CBOR([null, null, ["dcapi", SHA-256(CBOR([encryptionInfoBase64URL, origin]))]])`.
    ///
    /// - Parameters:
    ///   - encryptionInfoBase64URL: the **exact** unpadded base64url string from the incoming envelope (must be
    ///                              captured verbatim — re-encoding breaks the transcript).
    ///   - origin: the authenticated requesting origin as `scheme://host[:port]` (no path, no trailing slash).
    public static func buildSessionTranscript(
        encryptionInfoBase64URL: String,
        origin: String
    ) throws -> Data {
        let transcript = try sessionTranscript(encryptionInfoBase64URL: encryptionInfoBase64URL, origin: origin)
        guard let transcriptBytes = Data(transcript) else {
            throw HPKEResponseEncryptionError.cborEncodingFailure
        }
        return transcriptBytes
    }
    
    /// The SessionTranscript as a CBOR value, for structures that embed it (such as `DeviceAuthentication`).
    public static func sessionTranscript(
        encryptionInfoBase64URL: String,
        origin: String
    ) throws -> CBOR {
        guard !origin.isEmpty else {
            throw HPKEResponseEncryptionError.invalidOriginFormat
        }
        let dcapiInfo = CBOR(array: [
            CBOR(utf8String: encryptionInfoBase64URL),
            CBOR(utf8String: origin)
        ])
        guard let dcapiInfoBytes = Data(dcapiInfo) else {
            throw HPKEResponseEncryptionError.cborEncodingFailure
        }
        let digest = Data(SHA256.hash(data: dcapiInfoBytes))
        let handover = CBOR(array: [
            CBOR(utf8String: "dcapi"),
            CBOR(data: digest)
        ])
        return CBOR(array: [
            CBOR.cborNil(),
            CBOR.cborNil(),
            handover
        ])
    }
    
    /// SessionTranscript for the given request's `encryptionInfo` and the platform-provided origin.
    public static func sessionTranscript(info: EncryptionInfo, origin: URL?) throws -> CBOR {
        guard let origin else {
            throw HPKEResponseEncryptionError.missingOrigin
        }
        return try sessionTranscript(
            encryptionInfoBase64URL: info.rawBase64URL,
            origin: try formatOrigin(origin)
        )
    }
    
    /// Encrypts `deviceResponseCBOR` to the recipient public key using the baseline HPKE suite (DHKEM-P256-SHA256 /
    /// HKDF-SHA256 / AES-128-GCM) with `info = sessionTranscript` and empty AAD, then wraps the result as
    /// `["dcapi", {"enc": bstr, "cipherText": bstr}]`.
    public static func encryptDeviceResponse(
        _ deviceResponseCBOR: Data,
        info: EncryptionInfo,
        sessionTranscript: Data
    ) throws -> Data {
        let ciphersuite = HPKE.Ciphersuite(
            kem: .P256_HKDF_SHA256,
            kdf: .HKDF_SHA256,
            aead: .AES_GCM_128
        )
        let enc: Data
        let cipherText: Data
        do {
            var sender = try HPKE.Sender(
                recipientKey: info.recipientPublicKey,
                ciphersuite: ciphersuite,
                info: sessionTranscript
            )
            cipherText = try sender.seal(deviceResponseCBOR, authenticating: Data())
            enc = sender.encapsulatedKey
        } catch {
            throw HPKEResponseEncryptionError.hpkeFailure(underlying: error)
        }
        
        let encKey = CBOR(utf8String: "enc")
        let cipherKey = CBOR(utf8String: "cipherText")
        let response = CBOR(array: [
            CBOR(utf8String: "dcapi"),
            CBOR(dictionary: [
                encKey: CBOR(data: enc),
                cipherKey: CBOR(data: cipherText)
            ], keyOrderList: [encKey, cipherKey])
        ])
        guard let bytes = Data(response) else {
            throw HPKEResponseEncryptionError.cborEncodingFailure
        }
        return bytes
    }
    
    /// Strict variant: requires the request to contain `encryptionInfo`. Use this from flows where the specification
    /// mandates HPKE — the SMART Health Check-In v1 mdoc spec requires verifiers to reject plaintext responses, so
    /// producing one is a protocol violation.
    public static func encryptDeviceResponseStrict(
        deviceResponseCBOR: Data,
        rawRequest: IdentityDocumentWebPresentmentRawRequest,
        origin: URL?
    ) throws -> Data {
        guard let info = try extractEncryptionInfo(from: rawRequest.requestData) else {
            throw HPKEResponseEncryptionError.missingEncryptionInfo
        }
        return try finalizeEncryption(
            deviceResponseCBOR: deviceResponseCBOR,
            info: info,
            origin: origin
        )
    }
    
    // MARK: - Private
    
    private static let logger = Logger(
        subsystem: "org.smarthealthit.checkin",
        category: "HPKEResponseEncryption"
    )
    
    private static func finalizeEncryption(
        deviceResponseCBOR: Data,
        info: EncryptionInfo,
        origin: URL?
    ) throws -> Data {
        guard let origin else {
            throw HPKEResponseEncryptionError.missingOrigin
        }
        let originString = try formatOrigin(origin)
        let transcript = try buildSessionTranscript(
            encryptionInfoBase64URL: info.rawBase64URL,
            origin: originString
        )
        return try encryptDeviceResponse(
            deviceResponseCBOR,
            info: info,
            sessionTranscript: transcript
        )
    }
    
    private static func formatOrigin(_ url: URL) throws -> String {
        guard
            let scheme = url.scheme, !scheme.isEmpty,
            let host = url.host(percentEncoded: true), !host.isEmpty
        else {
            throw HPKEResponseEncryptionError.invalidOriginFormat
        }
        if let port = url.port {
            return "\(scheme)://\(host):\(port)"
        }
        return "\(scheme)://\(host)"
    }
    
    private static func parseCOSEP256PublicKey(_ keyCBOR: CBOR) throws -> P256.KeyAgreement.PublicKey {
        guard let dict = keyCBOR.dictionary else {
            throw HPKEResponseEncryptionError.invalidRecipientKey
        }
        guard
            let ktyCBOR = dict[CBOR(unsignedInteger: 1)],
            ktyCBOR == CBOR(unsignedInteger: 2)
        else {
            throw HPKEResponseEncryptionError.unsupportedKeyType
        }
        guard
            let crvCBOR = dict[CBOR(integer: -1)],
            crvCBOR == CBOR(unsignedInteger: 1)
        else {
            throw HPKEResponseEncryptionError.unsupportedCurveType
        }
        guard
            let xCoordinate = dict[CBOR(integer: -2)]?.data, xCoordinate.count == 32,
            let yCoordinate = dict[CBOR(integer: -3)]?.data, yCoordinate.count == 32
        else {
            throw HPKEResponseEncryptionError.invalidRecipientKey
        }
        var sec1 = Data(capacity: 65)
        sec1.append(0x04)
        sec1.append(xCoordinate)
        sec1.append(yCoordinate)
        do {
            return try P256.KeyAgreement.PublicKey(x963Representation: sec1)
        } catch {
            throw HPKEResponseEncryptionError.invalidRecipientKey
        }
    }
    
    private static func base64URLDecode(_ string: String) -> Data? {
        var normalized = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = normalized.count % 4
        if remainder > 0 {
            normalized.append(String(repeating: "=", count: 4 - remainder))
        }
        return Data(base64Encoded: normalized)
    }
}

// MARK: - Errors

public enum HPKEResponseEncryptionError: Error, LocalizedError {
    case missingEncryptionInfo
    case missingOrigin
    case invalidOriginFormat
    case invalidEncryptionInfoCBOR
    case invalidRecipientKey
    case unsupportedKeyType
    case unsupportedCurveType
    case hpkeFailure(underlying: Error)
    case cborEncodingFailure
    
    public var errorDescription: String? {
        switch self {
        case .missingEncryptionInfo:
            return "The verifier's request is missing required encryptionInfo for HPKE response encryption."
        case .missingOrigin:
            return "The authenticated requesting origin is unavailable; SessionTranscript cannot be constructed."
        case .invalidOriginFormat:
            return "The authenticated requesting origin is missing a scheme or host."
        case .invalidEncryptionInfoCBOR:
            return "The encryptionInfo CBOR is malformed or does not match the expected [\"dcapi\", {…}] shape."
        case .invalidRecipientKey:
            return "The recipient public key COSE_Key is malformed."
        case .unsupportedKeyType:
            return "The recipient public key must be COSE EC2."
        case .unsupportedCurveType:
            return "The recipient public key curve must be P-256."
        case .hpkeFailure(let underlying):
            return "HPKE encryption failed: \(underlying.localizedDescription)"
        case .cborEncodingFailure:
            return "Failed to encode CBOR for the dcapiResponse or SessionTranscript."
        }
    }
}
