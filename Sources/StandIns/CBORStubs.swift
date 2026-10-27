//
//  CBORStubs.swift
//  SMART Health Check-In
//

// Minimal CBOR implementation. The encoder follows RFC 8949, but only the major types the ISO 18013 code needs are
// covered: unsigned and negative integers, byte and text strings, arrays, maps, tags and the simple values. Floats,
// dates, indefinite-length items and the COSE types are not implemented.

public import Foundation

public final class CBOR {
    
    enum Value {
        case unsignedInteger(UInt64)
        case negativeInteger(Int64)
        case data(Data)
        case utf8String(String)
        case array([CBOR])
        case dictionary([CBOR: CBOR], keyOrder: [CBOR]?)
        case simple(UInt8)
    }
    
    let value: Value
    
    /// Tag attached to this value, itself a CBOR unsigned integer.
    public var tag: CBOR?
    
    init(value: Value, tag: CBOR? = nil) {
        self.value = value
        self.tag = tag
    }
    
    // MARK: - Creating Values
    
    public convenience init(unsignedInteger: UInt64) {
        self.init(value: .unsignedInteger(unsignedInteger))
    }
    
    public convenience init(integer: Int64) {
        if integer < 0 {
            self.init(value: .negativeInteger(integer))
        } else {
            self.init(value: .unsignedInteger(UInt64(integer)))
        }
    }
    
    public convenience init(data: Data) {
        self.init(value: .data(data))
    }
    
    public convenience init(utf8String: String) {
        self.init(value: .utf8String(utf8String))
    }
    
    public convenience init(array: [CBOR]) {
        self.init(value: .array(array))
    }
    
    public convenience init(dictionary: [CBOR: CBOR]) {
        self.init(value: .dictionary(dictionary, keyOrder: nil))
    }
    
    public convenience init(dictionary: [CBOR: CBOR], keyOrderList: [CBOR]) {
        self.init(value: .dictionary(dictionary, keyOrder: keyOrderList))
    }
    
    /// Copy of `cbor` with `tag` attached.
    public convenience init(cbor: CBOR, tag: CBOR?) {
        self.init(value: cbor.value, tag: tag)
    }
    
    public static func cborNil() -> CBOR {
        return CBOR(value: .simple(Self.simpleNull))
    }
    
    public static func cborTrue() -> CBOR {
        return CBOR(value: .simple(Self.simpleTrue))
    }
    
    public static func cborFalse() -> CBOR {
        return CBOR(value: .simple(Self.simpleFalse))
    }
    
    // MARK: - Reading Values
    
    public var string: String? {
        guard case .utf8String(let string) = value else {
            return nil
        }
        return string
    }
    
    public var data: Data? {
        guard case .data(let data) = value else {
            return nil
        }
        return data
    }
    
    public var array: [CBOR]? {
        guard case .array(let items) = value else {
            return nil
        }
        return items
    }
    
    public var dictionary: [CBOR: CBOR]? {
        guard case .dictionary(let dictionary, _) = value else {
            return nil
        }
        return dictionary
    }
    
    /// Indicates whether this is a byte string carrying an embedded CBOR object, per tag 24.
    public var isEmbeddedCBORData: Bool {
        guard case .data = value, case .unsignedInteger(Self.embeddedDataTag)? = tag?.value else {
            return false
        }
        return true
    }
    
    // MARK: - Encoding
    
    /// Byte string holding this value's CBOR encoding, tagged 24.
    public func encodeToEmbeddedCBORData() -> CBOR {
        return CBOR(value: .data(encodedData()), tag: CBOR(unsignedInteger: Self.embeddedDataTag))
    }
    
    func encodedData() -> Data {
        var bytes: [UInt8] = []
        encode(into: &bytes)
        return Data(bytes)
    }
    
    private func encode(into bytes: inout [UInt8]) {
        if case .unsignedInteger(let tagNumber)? = tag?.value {
            Self.appendHead(majorType: 6, argument: tagNumber, to: &bytes)
        }
        
        switch value {
        case .unsignedInteger(let number):
            Self.appendHead(majorType: 0, argument: number, to: &bytes)
            
        case .negativeInteger(let number):
            // CBOR encodes -1 - n, which for a negative n is the bitwise complement.
            Self.appendHead(majorType: 1, argument: ~UInt64(bitPattern: number), to: &bytes)
            
        case .data(let payload):
            Self.appendHead(majorType: 2, argument: UInt64(payload.count), to: &bytes)
            bytes.append(contentsOf: payload)
            
        case .utf8String(let string):
            let payload = Array(string.utf8)
            Self.appendHead(majorType: 3, argument: UInt64(payload.count), to: &bytes)
            bytes.append(contentsOf: payload)
            
        case .array(let items):
            Self.appendHead(majorType: 4, argument: UInt64(items.count), to: &bytes)
            for item in items {
                item.encode(into: &bytes)
            }
            
        case .dictionary(let dictionary, let keyOrder):
            let keys = Self.encodingOrder(for: dictionary, keyOrder: keyOrder)
            Self.appendHead(majorType: 5, argument: UInt64(keys.count), to: &bytes)
            for key in keys {
                key.encode(into: &bytes)
                dictionary[key]?.encode(into: &bytes)
            }
            
        case .simple(let simpleValue):
            Self.appendHead(majorType: 7, argument: UInt64(simpleValue), to: &bytes)
        }
    }
    
    private static func appendHead(majorType: UInt8, argument: UInt64, to bytes: inout [UInt8]) {
        let prefix = majorType << 5
        switch argument {
        case ..<24:
            bytes.append(prefix | UInt8(argument))
        case ..<0x100:
            bytes.append(prefix | 24)
            bytes.append(UInt8(argument))
        case ..<0x1_0000:
            bytes.append(prefix | 25)
            bytes.append(contentsOf: bigEndianBytes(of: UInt16(argument)))
        case ..<0x1_0000_0000:
            bytes.append(prefix | 26)
            bytes.append(contentsOf: bigEndianBytes(of: UInt32(argument)))
        default:
            bytes.append(prefix | 27)
            bytes.append(contentsOf: bigEndianBytes(of: argument))
        }
    }
    
    private static func bigEndianBytes<T: FixedWidthInteger>(of value: T) -> [UInt8] {
        return withUnsafeBytes(of: value.bigEndian) { Array($0) }
    }
    
    /// An explicit `keyOrderList` wins; anything it does not cover falls back to the core deterministic order of
    /// RFC 8949 §4.2.1, which sorts bytewise lexicographically over the encoded keys.
    private static func encodingOrder(for dictionary: [CBOR: CBOR], keyOrder: [CBOR]?) -> [CBOR] {
        func deterministicOrder() -> [CBOR] {
            return dictionary.keys.sorted {
                $0.encodedData().lexicographicallyPrecedes($1.encodedData())
            }
        }
        
        guard let keyOrder else {
            return deterministicOrder()
        }
        
        var seen = Set<CBOR>()
        var ordered: [CBOR] = []
        for key in keyOrder where dictionary.keys.contains(key) {
            if seen.insert(key).inserted {
                ordered.append(key)
            }
        }
        if ordered.count < dictionary.count {
            ordered.append(contentsOf: deterministicOrder().filter { !seen.contains($0) })
        }
        return ordered
    }
    
    // MARK: - Constants
    
    private static let simpleFalse: UInt8 = 20
    private static let simpleTrue: UInt8 = 21
    private static let simpleNull: UInt8 = 22
    private static let embeddedDataTag: UInt64 = 24
}

// MARK: - Equality

extension CBOR: Hashable {
    
    public static func == (lhs: CBOR, rhs: CBOR) -> Bool {
        switch (lhs.tag, rhs.tag) {
        case (nil, nil):
            break
        case (let lhsTag?, let rhsTag?) where lhsTag == rhsTag:
            break
        default:
            return false
        }
        return lhs.value == rhs.value
    }
    
    public func hash(into hasher: inout Hasher) {
        if case .unsignedInteger(let tagNumber)? = tag?.value {
            hasher.combine(tagNumber)
        }
        switch value {
        case .unsignedInteger(let number):
            hasher.combine(number)
        case .negativeInteger(let number):
            hasher.combine(number)
        case .data(let payload):
            hasher.combine(payload)
        case .utf8String(let string):
            hasher.combine(string)
        case .array(let items):
            hasher.combine(items.count)
        case .dictionary(let dictionary, _):
            hasher.combine(dictionary.count)
        case .simple(let simpleValue):
            hasher.combine(simpleValue)
        }
    }
}

extension CBOR.Value: Equatable {
    
    static func == (lhs: CBOR.Value, rhs: CBOR.Value) -> Bool {
        switch (lhs, rhs) {
        case (.unsignedInteger(let lhsNumber), .unsignedInteger(let rhsNumber)):
            return lhsNumber == rhsNumber
        case (.negativeInteger(let lhsNumber), .negativeInteger(let rhsNumber)):
            return lhsNumber == rhsNumber
        case (.data(let lhsPayload), .data(let rhsPayload)):
            return lhsPayload == rhsPayload
        case (.utf8String(let lhsString), .utf8String(let rhsString)):
            return lhsString == rhsString
        case (.array(let lhsItems), .array(let rhsItems)):
            return lhsItems == rhsItems
        case (.dictionary(let lhsDictionary, _), .dictionary(let rhsDictionary, _)):
            // Key ordering is an encoding concern only, so it does not take part in equality.
            return lhsDictionary == rhsDictionary
        case (.simple(let lhsValue), .simple(let rhsValue)):
            return lhsValue == rhsValue
        default:
            return false
        }
    }
}

// MARK: - Decoding

extension CBOR {
    
    /// Decodes the first CBOR item in `data`, or `nil` if the bytes are malformed or use an unsupported major type.
    public static func decode(from data: Data) -> CBOR? {
        var reader = Reader(bytes: Array(data))
        return reader.readItem()
    }
    
    private struct Reader {
        let bytes: [UInt8]
        var index: Int = 0
        
        mutating func readItem() -> CBOR? {
            guard index < bytes.count else {
                return nil
            }
            let initialByte = bytes[index]
            index += 1
            let majorType = initialByte >> 5
            let additionalInfo = initialByte & 0x1F
            
            // Major type 7 encodes the simple values in the head itself.
            if majorType == 7 {
                switch additionalInfo {
                case 20...23:
                    return CBOR(value: .simple(additionalInfo))
                case 24:
                    guard let simpleValue = readBytes(1)?.first else {
                        return nil
                    }
                    return CBOR(value: .simple(simpleValue))
                default:
                    return nil  // floats and the break stop code
                }
            }
            
            guard let argument = readArgument(additionalInfo) else {
                return nil
            }
            
            switch majorType {
            case 0:
                return CBOR(value: .unsignedInteger(argument))
                
            case 1:
                return CBOR(value: .negativeInteger(Int64(bitPattern: ~argument)))
                
            case 2:
                guard let payload = readBytes(argument) else {
                    return nil
                }
                return CBOR(value: .data(Data(payload)))
                
            case 3:
                guard let payload = readBytes(argument),
                      let string = String(bytes: payload, encoding: .utf8) else {
                    return nil
                }
                return CBOR(value: .utf8String(string))
                
            case 4:
                var items: [CBOR] = []
                for _ in 0..<argument {
                    guard let item = readItem() else {
                        return nil
                    }
                    items.append(item)
                }
                return CBOR(value: .array(items))
                
            case 5:
                var dictionary: [CBOR: CBOR] = [:]
                var keyOrder: [CBOR] = []
                for _ in 0..<argument {
                    guard let key = readItem(), let item = readItem() else {
                        return nil
                    }
                    dictionary[key] = item
                    keyOrder.append(key)
                }
                return CBOR(value: .dictionary(dictionary, keyOrder: keyOrder))
                
            case 6:
                guard let item = readItem() else {
                    return nil
                }
                item.tag = CBOR(unsignedInteger: argument)
                return item
                
            default:
                return nil
            }
        }
        
        mutating func readArgument(_ additionalInfo: UInt8) -> UInt64? {
            switch additionalInfo {
            case ..<24:
                return UInt64(additionalInfo)
            case 24:
                return readBytes(1).map { bigEndianValue(of: $0) }
            case 25:
                return readBytes(2).map { bigEndianValue(of: $0) }
            case 26:
                return readBytes(4).map { bigEndianValue(of: $0) }
            case 27:
                return readBytes(8).map { bigEndianValue(of: $0) }
            default:
                return nil  // 28...30 are reserved, 31 means indefinite length
            }
        }
        
        mutating func readBytes(_ count: UInt64) -> [UInt8]? {
            guard count <= UInt64(bytes.count - index) else {
                return nil
            }
            let end = index + Int(count)
            defer { index = end }
            return Array(bytes[index..<end])
        }
        
        func bigEndianValue(of slice: [UInt8]) -> UInt64 {
            return slice.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        }
    }
}

// MARK: - Data Conversion

extension Data {
    
    /// CBOR encoding of `value`, using the core deterministic map key order of RFC 8949 §4.2.1.
    public init?(_ value: CBOR) {
        self = value.encodedData()
    }
}
