//
//  OCRA.swift
//  
//
//  Created by Thiago Lima on 02/05/18.
//  Copyright © 2018. All rights reserved.
//

import Foundation

public class OCRA{
    
    internal var algorithm: OTPAlgorithm = OTPAlgorithm.HmacSHA1
    internal var ocraSuite: String
    internal var seed: String
    internal var counter: String
    internal var question: String
    internal var password: String
    internal var sessionInformation: String
    internal var timeStamp: String
    
    public init?(ocraSuite: String, seed: String, counter: String, question: String, password: String, sessionInformation: String, timeStamp: String){
        self.ocraSuite = ocraSuite
        self.seed = seed
        self.counter = counter
        self.question = question
        self.password = password
        self.sessionInformation = sessionInformation
        self.timeStamp = timeStamp
    }
    
    public func generate() -> String?{
        var codeDigits:Int = 0;
        var counterLength:Int = 0;
        var questionLength:Int = 0;
        var passwordLength:Int = 0;
        var sessionInformationLength:Int = 0;
        var timeStampLength:Int = 0;
        
        let elements = ocraSuite.components(separatedBy: ":")
        let cryptoFunction = elements[1]
        let dataInput = elements[2]
        
        if cryptoFunction.lowercased().contains("sha1"){
            algorithm = OTPAlgorithm.HmacSHA1
        }else if cryptoFunction.lowercased().contains("sha256"){
            algorithm = OTPAlgorithm.HmacSHA256
        }else if cryptoFunction.lowercased().contains("sha512"){
            algorithm = OTPAlgorithm.HmacSHA512
        }else{
            print("SHA algorithme unknow \(cryptoFunction)")
            return nil
        }
        
        // How many digits should we return
        codeDigits = Int(cryptoFunction.suffix(1))!
        
        // Counter
        if dataInput.lowercased().first == "c"{
            // Fix the length of the HEX string
            while counter.count < 16 {
                counter = "0" + counter
            }
            counterLength = 8
        }
        
        // Question - always 128 bytes
        if dataInput.lowercased().first == "q" || dataInput.lowercased().contains("-q"){
            while question.count < 256 {
                question = question + "0"
            }
            questionLength = 128
        }
        
        // Password
        if dataInput.lowercased().contains("psha1"){
            while password.count < 40 {
                password = "0" + password
            }
            passwordLength = 20
        }
        if dataInput.lowercased().contains("psha256"){
            while password.count < 64 {
                password = "0" + (password)
            }
            passwordLength = 32
        }
        if dataInput.lowercased().contains("psha512"){
            while password.count < 128 {
                password = "0" + (password)
            }
            passwordLength = 64
        }
        
        // sessionInformation
        if dataInput.lowercased().contains("s064"){
            while sessionInformation.count < 128 {
                sessionInformation = "0" + (sessionInformation)
            }
            sessionInformationLength = 64
        }
        if dataInput.lowercased().contains("s128"){
            while sessionInformation.count < 256 {
                sessionInformation = "0" + (sessionInformation)
            }
            sessionInformationLength = 128
        }
        if dataInput.lowercased().contains("s256"){
            while sessionInformation.count < 512 {
                sessionInformation = "0" + (sessionInformation)
            }
            sessionInformationLength = 256
        }
        if dataInput.lowercased().contains("s512"){
            while sessionInformation.count < 512 {
                sessionInformation = "0" + (sessionInformation)
            }
            sessionInformationLength = 256
        }
        
        // TimeStamp
        if dataInput.lowercased().contains("-t"){
            while timeStamp.count < 16 {
                timeStamp = "0" + (timeStamp)
            }
            timeStampLength = 8
        }
        
        // Remember to add "1" for the "00" byte delimiter
        let bufferSize: Int = ocraSuite.count + counterLength + questionLength + passwordLength + sessionInformationLength + timeStampLength + 1
        var msg = stringToUInt8Array(valor: ocraSuite, size: bufferSize)
        
        if counterLength > 0 {
            let bArray = dataWithHexString(hex: counter)?.bytes
            msg = arrayCopy(arrayFrom: bArray!, arrayTo: msg!, startIndex: ocraSuite.count + 1)
        }
        
        if questionLength > 0 {
            let bArray = dataWithHexString(hex: question)?.bytes
            msg = arrayCopy(arrayFrom: bArray!, arrayTo: msg!, startIndex: ocraSuite.count + 1 + counterLength)
        }
        
        if passwordLength > 0 {
            let bArray = dataWithHexString(hex: password)?.bytes
            msg = arrayCopy(arrayFrom: bArray!, arrayTo: msg!, startIndex: ocraSuite.count + 1 + counterLength + questionLength)
        }
        
        if sessionInformationLength > 0 {
            let bArray = dataWithHexString(hex: sessionInformation)?.bytes
            msg = arrayCopy(arrayFrom: bArray!, arrayTo: msg!, startIndex: ocraSuite.count + 1 + counterLength + questionLength + passwordLength)
        }
        
        if timeStampLength > 0 {
            let bArray = dataWithHexString(hex: timeStamp)?.bytes
            msg = arrayCopy(arrayFrom: bArray!, arrayTo: msg!, startIndex: ocraSuite.count + 1 + counterLength + questionLength + passwordLength + sessionInformationLength)
        }
        
        let key = dataWithHexString(hex: seed)
        
        let hmac = HMAC_kit(key: key!, message: Data(bytes: msg!), hashFunction: algorithm.toHashFunction())
        
        // Get offset
        let offset = Int((hmac.last ?? 0x00) & 0x0f)
        
        // Truncate HMAC into 32-bit integer (big-endian)
        let truncated = hmac.withUnsafeBytes { (bytePointer: UnsafePointer<UInt8>) -> UInt32 in
            let offsetPointer = bytePointer.advanced(by: offset)
            
            return offsetPointer.withMemoryRebound(to: UInt32.self, capacity: MemoryLayout<UInt32>.size) { $0.pointee.bigEndian }
        }
        
        // Discard most significant bit
        let discardedMSB = truncated & 0x7fffffff
        
        // Limit the number of digits
        let modulus = UInt32(pow(10, Float(codeDigits)))
        
        let stringValue = String(discardedMSB % modulus)
        
        // Create left padding if current digits count is not enough
        let paddingCount = Int(codeDigits) - stringValue.count
        if paddingCount != 0 {
            return String(repeating: "0", count: paddingCount) + stringValue
        } else {
            return stringValue
        }
    }
    
    func stringToUInt8Array(valor: String, size: Int) -> [UInt8]?{
        if let data = valor.data(using: .utf8) {
            var bytes = [UInt8](repeating: 0, count: size)
            data.copyBytes(to: &bytes, count: size)
            return bytes
        }
        return nil
    }
    
    func arrayCopy(arrayFrom: [UInt8], arrayTo: [UInt8], startIndex: Int) -> [UInt8]?{
        var bytes = arrayTo
        bytes[startIndex ..< startIndex+arrayFrom.count] = arrayFrom[0...arrayFrom.count-1]
        return bytes
    }
    
    func dataWithHexString(hex: String) -> Data? {
        var hex = hex
        var data = Data()
        while(hex.count > 0) {
            let subIndex = hex.index(hex.startIndex, offsetBy: 2)
            let c = String(hex[..<subIndex])
            hex = String(hex[subIndex...])
            var ch: UInt32 = 0
            Scanner(string: c).scanHexInt32(&ch)
            var char = UInt8(ch)
            data.append(&char, count: 1)
        }
        return data
    }
    
}
