//
//  SMARTHealthCheckinRequest.swift
//  SMARTHealthCheckin
//

import Foundation

// MARK: - Request

/// A SMART Health Check-In request from a verifier, conforming to the `org.smarthealthit.checkin.1` specification.
///
/// The verifier embeds the JSON-encoded form of this struct inside an mdoc ItemsRequest's
/// `requestInfo["org.smarthealthit.checkin.request"]` carrier.
public struct SMARTHealthCheckinRequest: Codable, Sendable, Equatable {

    public let type: String
    public let version: String
    public let id: String
    public let purpose: String?
    public let fhirVersions: [String]?
    public let items: [SMARTHealthCheckinRequestItem]

    public init(
        type: String = "smart-health-checkin-request",
        version: String = "1",
        id: String,
        purpose: String? = nil,
        fhirVersions: [String]? = nil,
        items: [SMARTHealthCheckinRequestItem]
    ) {
        self.type = type
        self.version = version
        self.id = id
        self.purpose = purpose
        self.fhirVersions = fhirVersions
        self.items = items
    }
}

/// A single item in a SMART Health Check-In request describing what the verifier wants to receive.
public struct SMARTHealthCheckinRequestItem: Codable, Sendable, Equatable, Identifiable {

    public let id: String
    public let title: String
    public let summary: String?
    public let required: Bool?
    public let content: SMARTHealthCheckinSelector
    public let accept: [String]

    public init(
        id: String,
        title: String,
        summary: String? = nil,
        required: Bool? = nil,
        content: SMARTHealthCheckinSelector,
        accept: [String]
    ) {
        self.id = id
        self.title = title
        self.summary = summary
        self.required = required
        self.content = content
        self.accept = accept
    }
}

// MARK: - Selector

/// Discriminated union describing how the verifier wants the wallet to source the artifact.
public enum SMARTHealthCheckinSelector: Codable, Sendable, Equatable {

    /// Pre-existing FHIR resources matching one or more profiles, value-set canonicals, or resource types.
    case selectionFHIR(profiles: [String]?, profilesFrom: [String]?, resourceTypes: [String]?)

    /// Form completion against a FHIR Questionnaire (canonical reference and/or inline definition).
    case formFHIR(questionnaireCanonical: String?, questionnaire: JSONValue?)

    /// Forward-compatible bucket for unknown selector kinds; preserves the raw payload.
    case extensionKind(name: String, raw: JSONValue)

    private enum CodingKeys: String, CodingKey {
        case kind, profiles, profilesFrom, resourceTypes, questionnaireCanonical, questionnaire
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: DynamicKey.self)
        guard let kindKey = DynamicKey(stringValue: "kind"),
              let kind = try container.decodeIfPresent(String.self, forKey: kindKey) else {
            throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "Missing selector 'kind'"))
        }
        switch kind {
        case "selection.fhir":
            // Mistyped members, or form members on a selection, make this one item unsupported
            guard let selection = Self.decodeSelection(container) else {
                self = .extensionKind(name: kind, raw: try JSONValue(from: decoder))
                return
            }
            self = selection
        case "form.fhir":
            guard let form = Self.decodeForm(container) else {
                self = .extensionKind(name: kind, raw: try JSONValue(from: decoder))
                return
            }
            self = form
        default:
            let raw = try JSONValue(from: decoder)
            self = .extensionKind(name: kind, raw: raw)
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: DynamicKey.self)
        switch self {
        case .selectionFHIR(let profiles, let profilesFrom, let resourceTypes):
            try container.encode("selection.fhir", forKey: DynamicKey(stringValue: "kind")!)
            if let profiles { try container.encode(profiles, forKey: DynamicKey(stringValue: "profiles")!) }
            if let profilesFrom { try container.encode(profilesFrom, forKey: DynamicKey(stringValue: "profilesFrom")!) }
            if let resourceTypes { try container.encode(resourceTypes, forKey: DynamicKey(stringValue: "resourceTypes")!) }
        case .formFHIR(let canonical, let questionnaire):
            try container.encode("form.fhir", forKey: DynamicKey(stringValue: "kind")!)
            if let canonical { try container.encode(canonical, forKey: DynamicKey(stringValue: "questionnaireCanonical")!) }
            if let questionnaire { try container.encode(questionnaire, forKey: DynamicKey(stringValue: "questionnaire")!) }
        case .extensionKind(_, let raw):
            try raw.encode(to: encoder)
        }
    }

    private static func decodeSelection(_ container: KeyedDecodingContainer<DynamicKey>) -> Self? {
        let formMembers = ["questionnaireCanonical", "questionnaire"].compactMap { DynamicKey(stringValue: $0) }
        guard !formMembers.contains(where: { container.contains($0) }) else {
            return nil
        }
        do {
            return .selectionFHIR(
                profiles: try decodeStringArray(container, key: "profiles"),
                profilesFrom: try decodeStringArray(container, key: "profilesFrom"),
                resourceTypes: try decodeStringArray(container, key: "resourceTypes")
            )
        } catch {
            return nil
        }
    }

    private static func decodeForm(_ container: KeyedDecodingContainer<DynamicKey>) -> Self? {
        do {
            return .formFHIR(
                questionnaireCanonical: try decodeString(container, key: "questionnaireCanonical"),
                questionnaire: try decodeValue(container, key: "questionnaire")
            )
        } catch {
            return nil
        }
    }

    private static func decodeStringArray(_ container: KeyedDecodingContainer<DynamicKey>, key: String) throws -> [String]? {
        guard let dynamicKey = DynamicKey(stringValue: key) else { return nil }
        return try container.decodeIfPresent([String].self, forKey: dynamicKey)
    }

    private static func decodeString(_ container: KeyedDecodingContainer<DynamicKey>, key: String) throws -> String? {
        guard let dynamicKey = DynamicKey(stringValue: key) else { return nil }
        return try container.decodeIfPresent(String.self, forKey: dynamicKey)
    }

    private static func decodeValue(_ container: KeyedDecodingContainer<DynamicKey>, key: String) throws -> JSONValue? {
        guard let dynamicKey = DynamicKey(stringValue: key) else { return nil }
        return try container.decodeIfPresent(JSONValue.self, forKey: dynamicKey)
    }
}
