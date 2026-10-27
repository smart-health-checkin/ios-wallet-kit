//
//  SMARTHealthCheckinDeviceRequest.swift
//  SMARTHealthCheckin
//

import Foundation

/// The parts of an ISO 18013-5 `DeviceRequest` the SMART Health Check-in wallet cares about, as plain Swift values.
///
/// Reading the CBOR happens here and nowhere else on the request side, so the validation rules can work on this
/// struct without touching a CBOR library.
struct SMARTHealthCheckinDeviceRequest: Equatable {
    
    struct DocRequest: Equatable {
        
        let documentType: String
        
        /// Text found under `requestInfo["org.smarthealthit.checkin.request"]`.
        let requestText: String?
        
        /// Whether `nameSpaces` asks for the check-in response element.
        let asksForResponseElement: Bool
        
        /// Whether the response element's `intentToRetain` is a boolean.
        let hasValidIntentToRetain: Bool
        
        let hasReaderAuth: Bool
    }
    
    let version: String?
    let docRequests: [DocRequest]
    
    /// Reads the CBOR `DeviceRequest`. Throws if the bytes are not a map with a `docRequests` array; doc requests whose
    /// `itemsRequest` cannot be decoded are skipped, since they may belong to another document type.
    static func parse(_ data: Data) throws -> SMARTHealthCheckinDeviceRequest {
        guard
            let root = CBOR.decode(from: data),
            let dictionary = root.dictionary,
            let docRequests = dictionary[CBOR(utf8String: "docRequests")]?.array
                else {
            throw SMARTHealthCheckinCredentialError.invalidCBOR
        }
        return SMARTHealthCheckinDeviceRequest(
            version: dictionary[CBOR(utf8String: "version")]?.string,
            docRequests: docRequests.compactMap(parseDocRequest)
        )
    }
    
    private static func parseDocRequest(_ docRequest: CBOR) -> DocRequest? {
        guard
            let dictionary = docRequest.dictionary,
            let itemsRequestBytes = dictionary[CBOR(utf8String: "itemsRequest")]?.data,
            let itemsRequest = CBOR.decode(from: itemsRequestBytes)?.dictionary,
            let documentType = itemsRequest[CBOR(utf8String: "docType")]?.string
                else {
            return nil
        }
        let requestText = itemsRequest[CBOR(utf8String: "requestInfo")]?
            .dictionary?[CBOR(utf8String: SMARTHealthCheckinCredential.requestCarrierKey)]?
            .string
        
        let intentToRetain = itemsRequest[CBOR(utf8String: "nameSpaces")]?
            .dictionary?[CBOR(utf8String: SMARTHealthCheckinCredential.namespace)]?
            .dictionary?[CBOR(utf8String: SMARTHealthCheckinCredential.elementResponse)]
        // CBOR false and true encode as the single bytes 0xF4 and 0xF5
        let firstByte = intentToRetain.flatMap { Data($0) }?.first
        return DocRequest(
            documentType: documentType,
            requestText: requestText,
            asksForResponseElement: intentToRetain != nil,
            hasValidIntentToRetain: firstByte == 0xF4 || firstByte == 0xF5,
            hasReaderAuth: dictionary[CBOR(utf8String: "readerAuth")] != nil
        )
    }
}
