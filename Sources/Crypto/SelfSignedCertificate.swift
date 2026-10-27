//
//  SelfSignedCertificate.swift
//  SMARTHealthCheckin
//

import CryptoKit
import Foundation
internal import SwiftASN1
internal import X509

/// A throwaway X.509 certificate for a P-256 key, signed with ecdsa-with-SHA256.
///
/// The SMART Health Check-in profile lets the wallet sign its own mdoc, so the certificate only has to carry the public
/// key for `x5chain`; no trust is attached to it.
enum SelfSignedCertificate {

    /// DER encoding of a self-signed certificate for `key`.
    static func makeDER(
        commonName: String,
        key: P256.Signing.PrivateKey,
        validFrom: Date,
        validUntil: Date
    ) throws -> Data {
        let name = try DistinguishedName {
            CommonName(commonName)
        }
        let privateKey = Certificate.PrivateKey(key)
        let certificate = try Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(),
            publicKey: privateKey.publicKey,
            notValidBefore: validFrom,
            notValidAfter: validUntil,
            issuer: name,
            subject: name,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: Certificate.Extensions(),
            issuerPrivateKey: privateKey
        )
        return Data(try certificate.serializeAsPEM().derBytes)
    }
}
