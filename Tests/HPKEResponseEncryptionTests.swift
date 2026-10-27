//
//  HPKEResponseEncryptionTests.swift
//  SMARTHealthCheckinTests
//

import CryptoKit
import Foundation
import Testing
@testable import SMARTHealthCheckin

struct HPKEResponseEncryptionTests {

    // MARK: - 1. End-to-end round-trip: verifier can decrypt wallet's dcapiResponse

    @Test func hpkeRoundTripDecryptsToOriginalPlaintext() throws {
        let recipientPrivate = P256.KeyAgreement.PrivateKey()
        let recipientPublic = recipientPrivate.publicKey
        let nonce = Data((0..<16).map { _ in UInt8.random(in: 0...UInt8.max) })
        let plaintext = Data("device-response-payload".utf8)
        let origin = "https://verifier.example.com"

        let encryptionInfoCBOR = Self.buildEncryptionInfoCBOR(
            recipientPublicKey: recipientPublic,
            nonce: nonce
        )
        let encryptionInfoBase64 = Self.base64URLEncode(encryptionInfoCBOR)
        let envelope = try JSONSerialization.data(withJSONObject: [
            "deviceRequest": Self.base64URLEncode(Data([0xA0])),
            "encryptionInfo": encryptionInfoBase64
        ])

        let info = try #require(try HPKEResponseEncryption.extractEncryptionInfo(from: envelope))
        #expect(info.nonce == nonce)
        #expect(info.rawBase64URL == encryptionInfoBase64)
        #expect(info.recipientPublicKey.x963Representation == recipientPublic.x963Representation)

        let transcript = try HPKEResponseEncryption.buildSessionTranscript(
            encryptionInfoBase64URL: info.rawBase64URL,
            origin: origin
        )
        let dcapiResponseBytes = try HPKEResponseEncryption.encryptDeviceResponse(
            plaintext,
            info: info,
            sessionTranscript: transcript
        )

        let decoded = try #require(CBOR.decode(from: dcapiResponseBytes))
        let outer = try #require(decoded.array)
        #expect(outer.count == 2)
        #expect(outer[0].string == "dcapi")

        let params = try #require(outer[1].dictionary)
        let enc = try #require(params[CBOR(utf8String: "enc")]?.data)
        let cipherText = try #require(params[CBOR(utf8String: "cipherText")]?.data)

        var recipient = try HPKE.Recipient(
            privateKey: recipientPrivate,
            ciphersuite: HPKE.Ciphersuite(
                kem: .P256_HKDF_SHA256,
                kdf: .HKDF_SHA256,
                aead: .AES_GCM_128
            ),
            info: transcript,
            encapsulatedKey: enc
        )
        let decrypted = try recipient.open(cipherText, authenticating: Data())
        #expect(decrypted == plaintext)
    }

    // MARK: - 2. SessionTranscript shape matches manually-constructed reference

    @Test func sessionTranscriptEqualsManualReference() throws {
        let encryptionInfoBase64 = "QUJDREVGRwHExyz-_abc"
        let origin = "https://verifier.example.com:8443"

        let actual = try HPKEResponseEncryption.buildSessionTranscript(
            encryptionInfoBase64URL: encryptionInfoBase64,
            origin: origin
        )

        let dcapiInfo = CBOR(array: [
            CBOR(utf8String: encryptionInfoBase64),
            CBOR(utf8String: origin)
        ])
        let dcapiInfoBytes = try #require(Data(dcapiInfo))
        let digest = Data(SHA256.hash(data: dcapiInfoBytes))
        let handover = CBOR(array: [
            CBOR(utf8String: "dcapi"),
            CBOR(data: digest)
        ])
        let expected = CBOR(array: [CBOR.cborNil(), CBOR.cborNil(), handover])
        let expectedBytes = try #require(Data(expected))

        #expect(actual == expectedBytes)
    }

    // MARK: - 3. COSE_Key decoding produces the expected P-256 public key

    @Test func coseKeyDecodingMatchesOriginalPublicKey() throws {
        let privateKey = P256.KeyAgreement.PrivateKey()
        let publicKey = privateKey.publicKey
        let nonce = Data(repeating: 0x11, count: 16)

        let encryptionInfoCBOR = Self.buildEncryptionInfoCBOR(
            recipientPublicKey: publicKey,
            nonce: nonce
        )
        let envelope = try JSONSerialization.data(withJSONObject: [
            "encryptionInfo": Self.base64URLEncode(encryptionInfoCBOR)
        ])

        let info = try #require(try HPKEResponseEncryption.extractEncryptionInfo(from: envelope))
        #expect(info.recipientPublicKey.x963Representation == publicKey.x963Representation)
    }

    // MARK: - 4. Missing origin → invalidOriginFormat

    @Test func emptyOriginThrowsInvalidOriginFormat() {
        #expect {
            _ = try HPKEResponseEncryption.buildSessionTranscript(
                encryptionInfoBase64URL: "abc",
                origin: ""
            )
        } throws: { error in
            guard case HPKEResponseEncryptionError.invalidOriginFormat = error else { return false }
            return true
        }
    }

    // MARK: - 5. Non-envelope requestData returns nil

    @Test func rawCBORRequestReturnsNilEncryptionInfo() throws {
        let rawCBOR = try #require(Data(CBOR(array: [
            CBOR(utf8String: "docRequests"),
            CBOR(array: [])
        ])))
        let info = try HPKEResponseEncryption.extractEncryptionInfo(from: rawCBOR)
        #expect(info == nil)
    }

    // MARK: - Helpers

    private static func buildEncryptionInfoCBOR(
        recipientPublicKey: P256.KeyAgreement.PublicKey,
        nonce: Data
    ) -> Data {
        let sec1 = recipientPublicKey.x963Representation
        let xCoordinate = sec1.subdata(in: 1..<33)
        let yCoordinate = sec1.subdata(in: 33..<65)

        let ktyKey = CBOR(unsignedInteger: 1)
        let crvKey = CBOR(integer: -1)
        let xKey = CBOR(integer: -2)
        let yKey = CBOR(integer: -3)
        let coseKey = CBOR(dictionary: [
            ktyKey: CBOR(unsignedInteger: 2),
            crvKey: CBOR(unsignedInteger: 1),
            xKey: CBOR(data: xCoordinate),
            yKey: CBOR(data: yCoordinate)
        ], keyOrderList: [ktyKey, crvKey, xKey, yKey])

        let nonceKey = CBOR(utf8String: "nonce")
        let pubKeyKey = CBOR(utf8String: "recipientPublicKey")
        let params = CBOR(dictionary: [
            nonceKey: CBOR(data: nonce),
            pubKeyKey: coseKey
        ], keyOrderList: [nonceKey, pubKeyKey])

        let root = CBOR(array: [
            CBOR(utf8String: "dcapi"),
            params
        ])
        return Data(root) ?? Data()
    }

    private static func base64URLEncode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
