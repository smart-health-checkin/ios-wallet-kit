//
//  SMARTHealthCheckinCredential.swift
//  SMARTHealthCheckin
//

import Foundation
import IdentityDocumentServices

/// Builds and parses ISO 18013-5 mDoc envelopes for the
/// `org.smarthealthit.checkin.1` SMART Health Check-In specification.
///
/// The spec follows Joshua Mandel's draft: the Verifier ships a JSON-encoded
/// `SMARTHealthCheckinRequest` inside `ItemsRequest.requestInfo["org.smarthealthit.checkin.request"]`,
/// and the Wallet returns a single issuer-signed element `smart_health_checkin_response`
/// whose value is a JSON-encoded `SMARTHealthCheckinResponse`.
public enum SMARTHealthCheckinCredential {

    /// mDoc document type for SMART Health Check-In v1.
    public static let documentType = "org.smarthealthit.checkin.1"

    /// mDoc namespace carrying the response element.
    public static let namespace = "org.smarthealthit.checkin"

    /// Stable element identifier for the response payload.
    public static let elementResponse = "smart_health_checkin_response"

    /// Map key under `ItemsRequest.requestInfo` that carries the JSON SMART request.
    public static let requestCarrierKey = "org.smarthealthit.checkin.request"

    // MARK: - Element Naming

    public static func displayName(for namespace: String, item: String? = nil) -> String {
        if namespace == Self.namespace {
            guard let item else {
                return "SMART Health Check-In"
            }
            switch item {
            case Self.elementResponse:
                return "SMART Health Check-In Response"
            default:
                return item
            }
        }
        return namespace
    }

    // MARK: - Request Extraction

    /// Returns true if the parsed request contains an mdoc DocumentRequest with this credential's docType.
    public static func containsCheckinDocType(in request: ISO18013MobileDocumentRequest) -> Bool {
        for presentmentRequest in request.presentmentRequests {
            for requestSet in presentmentRequest.documentRequestSets {
                for docRequest in requestSet.requests where docRequest.documentType == documentType {
                    return true
                }
            }
        }
        return false
    }

    // MARK: - Response Building

    /// Builds a CBOR-encoded ISO 18013-5 DeviceResponse carrying a single SMART Health Check-In document.
    ///
    /// The wallet's `SMARTHealthCheckinResponse` is JSON-encoded and placed in the `elementValue` of the single
    /// `smart_health_checkin_response` IssuerSignedItem under `namespace`. The document is signed with throwaway
    /// issuer and device keys, see `MobileDocumentSigner`.
    ///
    /// - Parameters:
    ///   - request: The parsed mdoc request from the verifier (used to confirm the docType is present).
    ///   - smartResponse: The SMART response payload chosen by the user.
    ///   - sessionTranscript: The transcript the device signature covers, from the validated request.
    static func buildResponse(
        for request: ISO18013MobileDocumentRequest,
        smartResponse: SMARTHealthCheckinResponse,
        sessionTranscript: Data
    ) async throws -> Data {
        guard containsCheckinDocType(in: request) else {
            throw SMARTHealthCheckinCredentialError.missingDocType
        }
        guard let transcript = CBOR.decode(from: sessionTranscript) else {
            throw SMARTHealthCheckinCredentialError.invalidCBOR
        }
        let jsonData = try JSONEncoder().encode(smartResponse)
        guard let jsonString = String(data: jsonData, encoding: .utf8) else {
            throw SMARTHealthCheckinCredentialError.invalidResponseJSON
        }
        let signer = MobileDocumentSigner(documentType: documentType, namespace: namespace)
        let document = try signer.makeDocument(
            elementIdentifier: elementResponse,
            elementValue: jsonString,
            sessionTranscript: transcript
        )
        return try buildDeviceResponse(documents: [document])
    }

    private static func buildDeviceResponse(documents: [CBOR]) throws -> Data {
        let versionKey = CBOR(utf8String: "version")
        let documentsKey = CBOR(utf8String: "documents")
        let statusKey = CBOR(utf8String: "status")

        let response = CBOR(dictionary: [
            versionKey: CBOR(utf8String: "1.0"),
            documentsKey: CBOR(array: documents),
            statusKey: CBOR(unsignedInteger: 0)
        ], keyOrderList: [versionKey, documentsKey, statusKey])

        guard let data = Data(response) else {
            throw SMARTHealthCheckinCredentialError.invalidCBOR
        }
        return data
    }
}

// MARK: - Errors

public enum SMARTHealthCheckinCredentialError: Error, LocalizedError {
    case invalidCBOR
    case missingRequestCarrier
    case missingDocType
    case invalidResponseJSON
    case invalidRequestEnvelope
    case invalidSMARTRequest(String)

    public var errorDescription: String? {
        switch self {
        case .invalidCBOR:
            return "The verifier's request could not be parsed as CBOR."
        case .missingRequestCarrier:
            return "The verifier's request is missing the SMART Health Check-In JSON payload."
        case .missingDocType:
            return "The verifier's request does not include the SMART Health Check-In document type."
        case .invalidResponseJSON:
            return "The SMART Health Check-In response could not be encoded as JSON."
        case .invalidRequestEnvelope:
            return "The verifier's request is not a deviceRequest and encryptionInfo envelope."
        case .invalidSMARTRequest(let reason):
            return "The verifier's SMART Health Check-In request is invalid. \(reason)"
        }
    }
}
