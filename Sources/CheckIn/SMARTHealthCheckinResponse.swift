//
//  SMARTHealthCheckinResponse.swift
//  SMARTHealthCheckin
//

import Foundation

// MARK: - Response

/// A SMART Health Check-In response from the wallet, conforming to the spec's
/// `SmartHealthCheckinResponse` shape.
public struct SMARTHealthCheckinResponse: Codable, Sendable, Equatable {

    public let type: String
    public let version: String
    public let requestId: String
    public let artifacts: [SMARTHealthArtifact]
    public let requestStatus: [SMARTHealthRequestItemStatus]

    public init(
        type: String = "smart-health-checkin-response",
        version: String = "1",
        requestId: String,
        artifacts: [SMARTHealthArtifact],
        requestStatus: [SMARTHealthRequestItemStatus]
    ) {
        self.type = type
        self.version = version
        self.requestId = requestId
        self.artifacts = artifacts
        self.requestStatus = requestStatus
    }
}

/// Status outcome for a single request item in the wallet's response.
public struct SMARTHealthRequestItemStatus: Codable, Sendable, Equatable {

    public let item: String
    public let status: SMARTHealthRequestItemStatusCode
    public let message: String?

    public init(item: String, status: SMARTHealthRequestItemStatusCode, message: String? = nil) {
        self.item = item
        self.status = status
        self.message = message
    }
}

/// Status codes the wallet may return per request item.
public enum SMARTHealthRequestItemStatusCode: String, Codable, Sendable, CaseIterable {
    case fulfilled
    case partial
    case unavailable
    case declined
    case unsupported
    case error
}
