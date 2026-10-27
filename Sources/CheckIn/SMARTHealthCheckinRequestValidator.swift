//
//  SMARTHealthCheckinRequestValidator.swift
//  SMARTHealthCheckin
//

import Foundation
import os.log

/// Wallet-side request checks for `org.smarthealthit.checkin.1`, following steps WRQ-2 to WRQ-9.
///
/// A step marked "fail" throws; every other problem becomes a warning in the result, so a slightly off request still
/// gets an answer.
enum SMARTHealthCheckinRequestValidator {
    
    struct ValidatedRequest: Sendable {
        
        let smartRequest: SMARTHealthCheckinRequest
        let encryptionInfo: HPKEResponseEncryption.EncryptionInfo
        
        /// CBOR bytes of the SessionTranscript, needed again to sign the response and to encrypt it.
        let sessionTranscript: Data
        
        let warnings: [String]
    }
    
    /// Validates the raw request data handed over by the platform.
    ///
    /// - parameter requestData: The JSON envelope `{"deviceRequest": "<base64url>", "encryptionInfo": "<base64url>"}`.
    /// - parameter origin:      The calling page's origin as reported by the platform.
    static func validate(requestData: Data, origin: URL?) throws -> ValidatedRequest {
        var warnings: [String] = []
        
        // WRQ-2: decode the DeviceRequest
        guard let envelope = try? JSONDecoder().decode(Envelope.self, from: requestData) else {
            throw SMARTHealthCheckinCredentialError.invalidRequestEnvelope
        }
        if envelope.deviceRequest.contains("=") {
            warnings.append("deviceRequest is padded base64url.")
        }
        guard let deviceRequestBytes = base64URLDecode(envelope.deviceRequest) else {
            throw SMARTHealthCheckinCredentialError.invalidRequestEnvelope
        }
        let deviceRequest = try SMARTHealthCheckinDeviceRequest.parse(deviceRequestBytes)
        
        // WRQ-3
        if deviceRequest.version != "1.0" {
            warnings.append("DeviceRequest version is not 1.0.")
        }
        
        // WRQ-4
        let matching = deviceRequest.docRequests.filter { $0.documentType == SMARTHealthCheckinCredential.documentType }
        guard let docRequest = matching.first else {
            throw SMARTHealthCheckinCredentialError.missingDocType
        }
        if matching.count > 1 {
            warnings.append("More than one DocRequest for the check-in document type; using the first.")
        }
        
        // WRQ-5
        guard let requestText = docRequest.requestText else {
            throw SMARTHealthCheckinCredentialError.missingRequestCarrier
        }
        if !docRequest.asksForResponseElement {
            warnings.append("nameSpaces does not request the check-in response element.")
        } else if !docRequest.hasValidIntentToRetain {
            warnings.append("intentToRetain is not a boolean.")
        }
        
        // WRQ-6
        let smartRequest = try validateSMARTRequest(requestText)
        
        // WRQ-7
        guard let encryptionInfo = try HPKEResponseEncryption.extractEncryptionInfo(from: requestData) else {
            throw HPKEResponseEncryptionError.missingEncryptionInfo
        }
        if encryptionInfo.nonce.isEmpty {
            warnings.append("encryptionInfo has no nonce.")
        }
        
        // WRQ-8
        let sessionTranscript = try HPKEResponseEncryption.sessionTranscript(info: encryptionInfo, origin: origin)
        guard let sessionTranscriptBytes = Data(sessionTranscript) else {
            throw HPKEResponseEncryptionError.cborEncodingFailure
        }
        
        // WRQ-9: reader authentication is never checked here, and never stops the exchange
        if docRequest.hasReaderAuth {
            warnings.append("readerAuth is present but not verified.")
        }
        
        for warning in warnings {
            logger.warning("Check-in request warning: \(warning, privacy: .public)")
        }
        return ValidatedRequest(
            smartRequest: smartRequest,
            encryptionInfo: encryptionInfo,
            sessionTranscript: sessionTranscriptBytes,
            warnings: warnings
        )
    }
    
    /// Reject a request of the wrong type or version, with mistyped members, or with missing, empty or duplicate item
    /// ids. Problems inside one item's `content` only make that item unsupported, see `SMARTHealthCheckinSelector`.
    static func validateSMARTRequest(_ text: String) throws -> SMARTHealthCheckinRequest {
        let request: SMARTHealthCheckinRequest
        do {
            request = try JSONDecoder().decode(SMARTHealthCheckinRequest.self, from: Data(text.utf8))
        } catch {
            throw SMARTHealthCheckinCredentialError.invalidSMARTRequest("The request JSON does not match the spec.")
        }
        guard request.type == "smart-health-checkin-request", request.version == "1" else {
            throw SMARTHealthCheckinCredentialError.invalidSMARTRequest("Unexpected request type or version.")
        }
        var seenIDs = Set<String>()
        for item in request.items {
            guard !item.id.isEmpty, seenIDs.insert(item.id).inserted else {
                throw SMARTHealthCheckinCredentialError.invalidSMARTRequest("Item ids must be non-empty and unique.")
            }
        }
        return request
    }
    
    // MARK: - Private
    
    private static let logger = Logger(subsystem: "org.smarthealthit.checkin", category: "RequestValidator")
    
    private struct Envelope: Decodable {
        let deviceRequest: String
    }
    
    private static func base64URLDecode(_ string: String) -> Data? {
        var normalized = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
            .replacingOccurrences(of: "=", with: "")
        let remainder = normalized.count % 4
        if remainder > 0 {
            normalized.append(String(repeating: "=", count: 4 - remainder))
        }
        return Data(base64Encoded: normalized)
    }
}
