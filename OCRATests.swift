//
//  OCRA.swift
//  
//
//  Created by Thiago Lima on 17/05/2018.
//  Copyright © 2018. All rights reserved.
//

import XCTest
import VoxAuth

class OCRATests: XCTestCase {
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    func testOCRA1() {
        let ocraSuite = "OCRA-1:HOTP-SHA512-8:QA10-T1M"
        let seed = "31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334"
        let counter = ""
        let question = "SIG1000000".bytes.toHexString()
        let password = ""
        let sessionInformation = ""
        let timeStamp = "132D0B6"
        
        let o = OCRA(ocraSuite: ocraSuite, seed: seed, counter: counter, question: question, password: password, sessionInformation: sessionInformation, timeStamp: timeStamp)!
        XCTAssertEqual(o.generate(), "77537423")
    }
    
    func testOCRA2() {
        let ocraSuite = "OCRA-1:HOTP-SHA256-8:QA08"
        let seed = "3132333435363738393031323334353637383930313233343536373839303132"
        let counter = ""
        let question = "SIG10000".bytes.toHexString()
        let password = ""
        let sessionInformation = ""
        let timeStamp = "132D0B6"
        
        let o = OCRA(ocraSuite: ocraSuite, seed: seed, counter: counter, question: question, password: password, sessionInformation: sessionInformation, timeStamp: timeStamp)!
        XCTAssertEqual(o.generate(), "53095496")
    }
    
    func testOCRA3() {
        let ocraSuite = "OCRA-1:HOTP-SHA512-8:QN08-T1M"
        let seed = "31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334"
        let counter = ""
        let question = "00000000"
        let password = ""
        let sessionInformation = ""
        let timeStamp = "132D0B6"
        
        let o = OCRA(ocraSuite: ocraSuite, seed: seed, counter: counter, question: question, password: password, sessionInformation: sessionInformation, timeStamp: timeStamp)!
        XCTAssertEqual(o.generate(), "95209754")
    }
    
    func testOCRA4() {
        let ocraSuite = "OCRA-1:HOTP-SHA256-8:QN08-PSHA1"
        let seed = "3132333435363738393031323334353637383930313233343536373839303132"
        let counter = ""
        let question = "00000000"
        let password = "7110eda4d09e062aa5e4a390b0a572ac0d2c0220"
        let sessionInformation = ""
        let timeStamp = ""
        
        let o = OCRA(ocraSuite: ocraSuite, seed: seed, counter: counter, question: question, password: password, sessionInformation: sessionInformation, timeStamp: timeStamp)!
        XCTAssertEqual(o.generate(), "83238735")
    }
    
    func testOCRA5() {
        let ocraSuite = "OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1"
        let seed = "3132333435363738393031323334353637383930313233343536373839303132"
        let counter = "0"
        let question = "BC614E"
        let password = "7110eda4d09e062aa5e4a390b0a572ac0d2c0220"
        let sessionInformation = ""
        let timeStamp = ""
        
        let o = OCRA(ocraSuite: ocraSuite, seed: seed, counter: counter, question: question, password: password, sessionInformation: sessionInformation, timeStamp: timeStamp)!
        XCTAssertEqual(o.generate(), "65347737")
    }
    
}
