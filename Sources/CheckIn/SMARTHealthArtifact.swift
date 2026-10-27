//
//  SMARTHealthArtifact.swift
//  SMARTHealthCheckin
//

import Foundation

// MARK: - Artifact

/// Discriminated union of artifact payloads a wallet may return.
public enum SMARTHealthArtifact: Codable, Sendable, Equatable {

    /// One or more SMART Health Cards (verifiable credential JWS strings).
    case smartHealthCard(id: String, fulfills: [String], verifiableCredential: [String])

    /// A FHIR Resource or Bundle in raw JSON form, paired with an explicit FHIR version.
    case rawFHIRJSON(id: String, fulfills: [String], fhirVersion: String, value: JSONValue)

    /// Forward-compatible bucket for unknown media types; preserves the raw artifact JSON.
    case extensionMediaType(id: String, mediaType: String, fulfills: [String], raw: JSONValue)

    private enum CodingKeys: String, CodingKey {
        case id, mediaType, fulfills, value, fhirVersion
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let mediaType = try container.decode(String.self, forKey: .mediaType)
        let id = try container.decode(String.self, forKey: .id)
        let fulfills = try container.decode([String].self, forKey: .fulfills)
        switch mediaType {
        case "application/smart-health-card":
            let value = try container.decode(SHCValue.self, forKey: .value)
            self = .smartHealthCard(id: id, fulfills: fulfills, verifiableCredential: value.verifiableCredential)
        case "application/fhir+json":
            let fhirVersion = try container.decode(String.self, forKey: .fhirVersion)
            let value = try container.decode(JSONValue.self, forKey: .value)
            self = .rawFHIRJSON(id: id, fulfills: fulfills, fhirVersion: fhirVersion, value: value)
        default:
            let raw = try JSONValue(from: decoder)
            self = .extensionMediaType(id: id, mediaType: mediaType, fulfills: fulfills, raw: raw)
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .smartHealthCard(let id, let fulfills, let verifiableCredential):
            try container.encode(id, forKey: .id)
            try container.encode("application/smart-health-card", forKey: .mediaType)
            try container.encode(fulfills, forKey: .fulfills)
            try container.encode(SHCValue(verifiableCredential: verifiableCredential), forKey: .value)
        case .rawFHIRJSON(let id, let fulfills, let fhirVersion, let value):
            try container.encode(id, forKey: .id)
            try container.encode("application/fhir+json", forKey: .mediaType)
            try container.encode(fhirVersion, forKey: .fhirVersion)
            try container.encode(fulfills, forKey: .fulfills)
            try container.encode(value, forKey: .value)
        case .extensionMediaType(_, _, _, let raw):
            try raw.encode(to: encoder)
        }
    }

    private struct SHCValue: Codable, Equatable {
        let verifiableCredential: [String]
    }
}

// MARK: - Media Type Constants

public extension SMARTHealthArtifact {
    static let mediaTypeFHIR = "application/fhir+json"
    static let mediaTypeSMARTHealthCard = "application/smart-health-card"
}

// MARK: - Artifact Factories

public extension SMARTHealthArtifact {

    /// Wraps any encodable FHIR resource, e.g. a resource from the app's FHIR library.
    static func fhirResource(
        _ resource: some Encodable,
        id: String,
        fulfills: [String],
        fhirVersion: String = "4.0.1"
    ) throws -> SMARTHealthArtifact {
        try fhirJSON(JSONEncoder().encode(resource), id: id, fulfills: fulfills, fhirVersion: fhirVersion)
    }

    /// Wraps a FHIR resource that is already serialized as JSON.
    static func fhirJSON(
        _ data: Data,
        id: String,
        fulfills: [String],
        fhirVersion: String = "4.0.1"
    ) throws -> SMARTHealthArtifact {
        .rawFHIRJSON(
            id: id,
            fulfills: fulfills,
            fhirVersion: fhirVersion,
            value: try JSONDecoder().decode(JSONValue.self, from: data)
        )
    }
}

// MARK: - JSONValue

/// Minimal JSON value type used to round-trip arbitrary JSON without losing structure or order.
///
/// Used for selector questionnaires, FHIR resource bodies, and unknown extension payloads.
/// Object key order is preserved to match the original wire form.
public enum JSONValue: Codable, Sendable, Equatable {

    case null
    case bool(Bool)
    case number(Double)
    case integer(Int64)
    case string(String)
    case array([JSONValue])
    case object([(String, JSONValue)])

    public static func == (lhs: JSONValue, rhs: JSONValue) -> Bool {
        switch (lhs, rhs) {
        case (.null, .null): return true
        case (.bool(let l), .bool(let r)): return l == r
        case (.number(let l), .number(let r)): return l == r
        case (.integer(let l), .integer(let r)): return l == r
        case (.string(let l), .string(let r)): return l == r
        case (.array(let l), .array(let r)): return l == r
        case (.object(let l), .object(let r)):
            guard l.count == r.count else { return false }
            for (lhsPair, rhsPair) in zip(l, r) where lhsPair.0 != rhsPair.0 || lhsPair.1 != rhsPair.1 {
                return false
            }
            return true
        default: return false
        }
    }

    public init(from decoder: Decoder) throws {
        if let container = try? decoder.singleValueContainer(), container.decodeNil() {
            self = .null
            return
        }
        if let container = try? decoder.singleValueContainer() {
            if let value = try? container.decode(Bool.self) {
                self = .bool(value)
                return
            }
            if let value = try? container.decode(Int64.self) {
                self = .integer(value)
                return
            }
            if let value = try? container.decode(Double.self) {
                self = .number(value)
                return
            }
            if let value = try? container.decode(String.self) {
                self = .string(value)
                return
            }
        }
        if var array = try? decoder.unkeyedContainer() {
            var items: [JSONValue] = []
            while !array.isAtEnd {
                items.append(try array.decode(JSONValue.self))
            }
            self = .array(items)
            return
        }
        let object = try decoder.container(keyedBy: DynamicKey.self)
        var pairs: [(String, JSONValue)] = []
        for key in object.allKeys {
            pairs.append((key.stringValue, try object.decode(JSONValue.self, forKey: key)))
        }
        self = .object(pairs)
    }

    public func encode(to encoder: Encoder) throws {
        switch self {
        case .null:
            var container = encoder.singleValueContainer()
            try container.encodeNil()
        case .bool(let value):
            var container = encoder.singleValueContainer()
            try container.encode(value)
        case .integer(let value):
            var container = encoder.singleValueContainer()
            try container.encode(value)
        case .number(let value):
            var container = encoder.singleValueContainer()
            try container.encode(value)
        case .string(let value):
            var container = encoder.singleValueContainer()
            try container.encode(value)
        case .array(let items):
            var container = encoder.unkeyedContainer()
            for item in items {
                try container.encode(item)
            }
        case .object(let pairs):
            var container = encoder.container(keyedBy: DynamicKey.self)
            for (key, value) in pairs {
                guard let dynamicKey = DynamicKey(stringValue: key) else { continue }
                try container.encode(value, forKey: dynamicKey)
            }
        }
    }
}

// MARK: - Internal: Dynamic Key

struct DynamicKey: CodingKey {
    var stringValue: String
    var intValue: Int? { nil }

    init?(stringValue: String) {
        self.stringValue = stringValue
    }

    init?(intValue: Int) {
        self.stringValue = String(intValue)
    }
}
