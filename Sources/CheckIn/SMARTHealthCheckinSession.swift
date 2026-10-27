//
//  SMARTHealthCheckinSession.swift
//  SMARTHealthCheckin
//

import Foundation
import IdentityDocumentServices

/// One validated `org.smarthealthit.checkin.1` request, from the platform's raw request to the encrypted response.
///
/// Wraps the mdoc details (transcript, signing, HPKE) so callers only deal with the SMART request and response.
public struct SMARTHealthCheckinSession: Sendable {
    
    /// The SMART request to show to the person.
    public let smartRequest: SMARTHealthCheckinRequest
    
    /// Problems with the request that did not stop it from being answered.
    public let warnings: [String]
    
    private let validated: SMARTHealthCheckinRequestValidator.ValidatedRequest
    
    /// Validates the raw request (spec §8.4) and throws where the spec says the wallet must not respond.
    ///
    /// - Parameters:
    ///   - requestData: `IdentityDocumentWebPresentmentRawRequest.requestData`.
    ///   - origin: The calling page's origin, as reported by the platform.
    public init(requestData: Data, origin: URL?) throws {
        let validated = try SMARTHealthCheckinRequestValidator.validate(requestData: requestData, origin: origin)
        self.validated = validated
        self.smartRequest = validated.smartRequest
        self.warnings = validated.warnings
    }
    
    /// Signs `response` as an mdoc and encrypts it to the verifier, ready to hand back to the platform.
    public func encryptedResponse(
        for response: SMARTHealthCheckinResponse,
        in request: ISO18013MobileDocumentRequest
    ) async throws -> Data {
        let deviceResponse = try await SMARTHealthCheckinCredential.buildResponse(
            for: request,
            smartResponse: response,
            sessionTranscript: validated.sessionTranscript
        )
        return try HPKEResponseEncryption.encryptDeviceResponse(
            deviceResponse,
            info: validated.encryptionInfo,
            sessionTranscript: validated.sessionTranscript
        )
    }
}
