/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.xml.security.test.stax.encryption;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;

import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.stax.ext.InboundXMLSec;
import org.apache.xml.security.stax.ext.OutboundXMLSec;
import org.apache.xml.security.stax.ext.SecurePart;
import org.apache.xml.security.stax.ext.XMLSec;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.test.stax.utils.StAX2DOM;
import org.apache.xml.security.test.stax.utils.XMLSecEventAllocator;
import org.apache.xml.security.test.stax.utils.XmlReaderToWriter;
import org.apache.xml.security.utils.EncryptionConstants;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * StAX-path tests for ML-KEM key transport with AES-256-GCM content encryption, using the W3C
 * "XML Security: Generic Hybrid Cipher" key transport structure
 * (https://www.w3.org/TR/xmlsec-generic-hybrid/, see SANTUARIO-633) - the same structure exercised
 * by the DOM {@code XMLCipher} API in {@code XMLEncryptionMLKEMTest}.
 */
class StaxMLKEMEncryptionTest {

    private static boolean mlKemAvailable;
    private static boolean bcAddedForTheTest;
    private static final Map<String, KeyPair> keyPairs = new HashMap<>();
    private final XMLInputFactory xmlInputFactory;

    @BeforeAll
    static void setUp() {
        org.apache.xml.security.Init.init();
        if (Security.getProvider("BC") == null) {
            try {
                Class<?> cls = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
                Provider bc = (Provider) cls.getConstructor().newInstance();
                Security.insertProviderAt(bc, 2);
                bcAddedForTheTest = true;
            } catch (ReflectiveOperationException e) {
                mlKemAvailable = false;
                return;
            }
        }
        try {
            for (String alg : new String[]{"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"}) {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance(alg, "BC");
                keyPairs.put(alg, kpg.generateKeyPair());
            }
            // javax.crypto.KEM (JEP 452) is only available since Java 21
            Class.forName("javax.crypto.KEM");
            mlKemAvailable = true;
        } catch (Exception | LinkageError e) {
            mlKemAvailable = false;
        }
    }

    @AfterAll
    static void cleanup() {
        if (bcAddedForTheTest) {
            Security.removeProvider("BC");
        }
    }

    public StaxMLKEMEncryptionTest() throws Exception {
        org.apache.xml.security.Init.init();
        xmlInputFactory = XMLInputFactory.newInstance();
        xmlInputFactory.setEventAllocator(new XMLSecEventAllocator());
    }

    @ParameterizedTest
    @CsvSource({
        EncryptionConstants.ALGO_ID_KEYTRANSPORT_MLKEM_512  + ",ML-KEM-512",
        EncryptionConstants.ALGO_ID_KEYTRANSPORT_MLKEM_768  + ",ML-KEM-768",
        EncryptionConstants.ALGO_ID_KEYTRANSPORT_MLKEM_1024 + ",ML-KEM-1024"
    })
    void testMLKEMEncryptDecrypt(String keyEncapsulationUri, String jcaAlgorithm) throws Exception {
        Assumptions.assumeTrue(mlKemAvailable, "ML-KEM requires BouncyCastle 1.84+ and Java 21+ (javax.crypto.KEM)");

        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.ENCRYPTION);
        properties.setActions(actions);

        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(256);
        SecretKey cek = keygen.generateKey();
        properties.setEncryptionKey(cek);
        properties.setEncryptionSymAlgorithm("http://www.w3.org/2009/xmlenc11#aes256-gcm");

        KeyPair kp = keyPairs.get(jcaAlgorithm);
        properties.setEncryptionKeyTransportAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_GENERIC_HYBRID);
        properties.setEncryptionKeyEncapsulationAlgorithm(keyEncapsulationUri);
        properties.setEncryptionDataEncapsulationAlgorithm(EncryptionConstants.ALGO_ID_KEYWRAP_AES256);
        properties.setEncryptionTransportKey(kp.getPublic());

        SecurePart securePart = new SecurePart(
            new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Element);
        properties.addEncryptionPart(securePart);

        byte[] output = process("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml", properties);

        // Verify the produced XML carries the spec's element names, per
        // https://www.w3.org/TR/xmlsec-generic-hybrid/ section 6.1 "Key Transport Example"
        String serialized = new String(output, StandardCharsets.UTF_8);
        assertTrue(serialized.contains("GenericHybridCipherMethod"), "Missing GenericHybridCipherMethod element");
        assertTrue(serialized.contains("KeyEncapsulationMethod"), "Missing KeyEncapsulationMethod element");
        assertTrue(serialized.contains("DataEncapsulationMethod"), "Missing DataEncapsulationMethod element");
        assertTrue(serialized.contains("http://www.w3.org/2010/xmlsec-ghc#generic-hybrid"),
                "Missing Generic Hybrid Cipher EncryptionMethod algorithm");

        Document document;
        try (InputStream is = new ByteArrayInputStream(output)) {
            document = XMLUtils.read(is, false);
        }

        NodeList nodeList = document.getElementsByTagNameNS("urn:example:po", "PaymentInfo");
        assertEquals(0, nodeList.getLength());

        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(0, nodeList.getLength());

        nodeList = document.getElementsByTagNameNS(
            XMLSecurityConstants.TAG_xenc_EncryptedData.getNamespaceURI(),
            XMLSecurityConstants.TAG_xenc_EncryptedData.getLocalPart()
        );
        assertEquals(1, nodeList.getLength());

        Document decrypted = decryptUsingDOM(document, kp.getPrivate());

        nodeList = decrypted.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(1, nodeList.getLength());
    }

    @ParameterizedTest
    @CsvSource({
        EncryptionConstants.ALGO_ID_KEYTRANSPORT_MLKEM_512  + ",ML-KEM-512",
        EncryptionConstants.ALGO_ID_KEYTRANSPORT_MLKEM_768  + ",ML-KEM-768",
        EncryptionConstants.ALGO_ID_KEYTRANSPORT_MLKEM_1024 + ",ML-KEM-1024"
    })
    void testMLKEMStaxEncryptStaxDecrypt(String keyEncapsulationUri, String jcaAlgorithm) throws Exception {
        Assumptions.assumeTrue(mlKemAvailable, "ML-KEM requires BouncyCastle 1.84+ and Java 21+ (javax.crypto.KEM)");

        XMLSecurityProperties encryptProperties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.ENCRYPTION);
        encryptProperties.setActions(actions);

        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(256);
        SecretKey cek = keygen.generateKey();
        encryptProperties.setEncryptionKey(cek);
        encryptProperties.setEncryptionSymAlgorithm("http://www.w3.org/2009/xmlenc11#aes256-gcm");

        KeyPair kp = keyPairs.get(jcaAlgorithm);
        encryptProperties.setEncryptionKeyTransportAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_GENERIC_HYBRID);
        encryptProperties.setEncryptionKeyEncapsulationAlgorithm(keyEncapsulationUri);
        encryptProperties.setEncryptionDataEncapsulationAlgorithm(EncryptionConstants.ALGO_ID_KEYWRAP_AES256);
        encryptProperties.setEncryptionTransportKey(kp.getPublic());

        SecurePart securePart = new SecurePart(
            new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Element);
        encryptProperties.addEncryptionPart(securePart);

        byte[] encrypted = process("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml", encryptProperties);

        XMLSecurityProperties decryptProperties = new XMLSecurityProperties();
        decryptProperties.setDecryptionKey(kp.getPrivate());
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(decryptProperties);
        XMLStreamReader xmlStreamReader =
            xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(encrypted));
        XMLStreamReader securityStreamReader = inboundXMLSec.processInMessage(xmlStreamReader, null, null);

        Document decrypted = StAX2DOM.readDoc(securityStreamReader);

        NodeList nodeList = decrypted.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(1, nodeList.getLength());
    }

    private byte[] process(String inputXmlFile, XMLSecurityProperties properties) throws Exception {
        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, StandardCharsets.UTF_8.name());
        try (InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream(inputXmlFile)) {
            XMLStreamReader xmlStreamReader = null;
            try {
                xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);
                XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
                return baos.toByteArray();
            } finally {
                if (xmlStreamReader != null) {
                    xmlStreamReader.close();
                }
            }
        } finally {
            xmlStreamWriter.close();
        }
    }

    private Document decryptUsingDOM(Document document, Key privateKey) throws Exception {
        NodeList nodeList = document.getElementsByTagNameNS(
            XMLSecurityConstants.TAG_xenc_EncryptedData.getNamespaceURI(),
            XMLSecurityConstants.TAG_xenc_EncryptedData.getLocalPart()
        );
        Element ee = (Element) nodeList.item(0);

        XMLCipher cipher = XMLCipher.getInstance();
        cipher.init(XMLCipher.DECRYPT_MODE, null);
        EncryptedData encryptedData = cipher.loadEncryptedData(document, ee);

        XMLCipher kwCipher = XMLCipher.getInstance();
        kwCipher.init(XMLCipher.UNWRAP_MODE, privateKey);
        KeyInfo ki = encryptedData.getKeyInfo();
        EncryptedKey encryptedKey = ki.itemEncryptedKey(0);
        Key symmetricKey = kwCipher.decryptKey(
            encryptedKey, encryptedData.getEncryptionMethod().getAlgorithm()
        );

        cipher.init(XMLCipher.DECRYPT_MODE, symmetricKey);
        return cipher.doFinal(document, ee);
    }
}
