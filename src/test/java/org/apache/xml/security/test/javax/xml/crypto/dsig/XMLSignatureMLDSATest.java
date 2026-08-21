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
package org.apache.xml.security.test.javax.xml.crypto.dsig;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.util.Locale;

import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;

import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.test.javax.xml.crypto.KeySelectors;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/**
 * Tests for ML-DSA (FIPS 204) XML digital signatures via the
 * {@code javax.xml.crypto.dsig.XMLSignatureFactory} DOM API.
 *
 * <p>The key material is stored in {@code mldsa.p12} (PKCS12, password "security"),
 * pre-generated with BouncyCastle 1.81+ and committed as a test resource.
 * The test requires BouncyCastle on the runtime classpath to supply the ML-DSA
 * JCA provider; compile-time BC classes are deliberately avoided so the default
 * build (without {@code -P bouncycastle}) still compiles cleanly.
 *
 * <p>Run with the Maven {@code bouncycastle} profile:
 * <pre>mvn test -Dtest=XMLSignatureMLDSATest -P bouncycastle</pre>
 */
class XMLSignatureMLDSATest extends XMLSignatureAbstract {

    static final String MLDSA_KS =
            "src/test/resources/org/apache/xml/security/samples/input/mldsa.p12";
    static final String MLDSA_KS_PASSWORD = "security";
    static final String MLDSA_KS_TYPE = "PKCS12";

    private static boolean mlDsaAvailable;
    private static boolean bcAddedForTheTest;
    private static KeyStore keyStore;

    @BeforeAll
    static void setUp() {
        Security.insertProviderAt(
                new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI(), 1);

        if (Security.getProvider("BC") == null) {
            try {
                Class<?> cls = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
                Provider bc = (Provider) cls.getConstructor().newInstance();
                Security.addProvider(bc);
                bcAddedForTheTest = true;
            } catch (ReflectiveOperationException e) {
                mlDsaAvailable = false;
                return;
            }
        }

        try {
            keyStore = KeyStore.getInstance(MLDSA_KS_TYPE);
            keyStore.load(Files.newInputStream(Path.of(MLDSA_KS)),
                    MLDSA_KS_PASSWORD.toCharArray());
            // probe that ML-DSA is actually supported by the loaded provider
            keyStore.getKey("ml-dsa-65", MLDSA_KS_PASSWORD.toCharArray());
            mlDsaAvailable = true;
        } catch (Exception e) {
            mlDsaAvailable = false;
        }
    }

    @AfterAll
    static void tearDown() {
        if (bcAddedForTheTest) {
            Security.removeProvider("BC");
        }
    }

    @ParameterizedTest
    @CsvSource({
        XMLSignature.ALGO_ID_SIGNATURE_MLDSA_44 + ",ml-dsa-44",
        XMLSignature.ALGO_ID_SIGNATURE_MLDSA_65 + ",ml-dsa-65",
        XMLSignature.ALGO_ID_SIGNATURE_MLDSA_87 + ",ml-dsa-87",
    })
    void testMLDSASignAndVerify(String signatureAlgorithmURI, String alias) throws Exception {
        Assumptions.assumeTrue(mlDsaAvailable, "ML-DSA requires BouncyCastle 1.81+");
        byte[] signedXml = doSignWithJcpApi(signatureAlgorithmURI, alias, false);
        Assertions.assertNotNull(signedXml);
        assertValidSignatureWithJcpApi(signedXml, false);
    }

    @ParameterizedTest
    @CsvSource({
        XMLSignature.ALGO_ID_SIGNATURE_MLDSA_44 + ",ml-dsa-44",
        XMLSignature.ALGO_ID_SIGNATURE_MLDSA_65 + ",ml-dsa-65",
        XMLSignature.ALGO_ID_SIGNATURE_MLDSA_87 + ",ml-dsa-87",
    })
    void testMLDSATamperedSignatureRejected(String signatureAlgorithmURI, String alias) throws Exception {
        Assumptions.assumeTrue(mlDsaAvailable, "ML-DSA requires BouncyCastle 1.81+");
        byte[] signedXml = doSignWithJcpApi(signatureAlgorithmURI, alias, false);
        byte[] tampered = flipSignatureValueBit(signedXml);
        Assertions.assertFalse(isValidSignature(tampered, new KeySelectors.RawX509KeySelector()),
                "verification must fail when the signature value is altered");
    }

    @ParameterizedTest
    @CsvSource({
        XMLSignature.ALGO_ID_SIGNATURE_MLDSA_44 + ",ml-dsa-44",
        XMLSignature.ALGO_ID_SIGNATURE_MLDSA_65 + ",ml-dsa-65",
        XMLSignature.ALGO_ID_SIGNATURE_MLDSA_87 + ",ml-dsa-87",
    })
    void testMLDSAWrongKeyFailsVerification(String signatureAlgorithmURI, String alias) throws Exception {
        Assumptions.assumeTrue(mlDsaAvailable, "ML-DSA requires BouncyCastle 1.81+");
        byte[] signedXml = doSignWithJcpApi(signatureAlgorithmURI, alias, false);
        // a different key pair of the same ML-DSA parameter set
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(alias.toUpperCase(Locale.ROOT), "BC");
        PublicKey wrongKey = kpg.generateKeyPair().getPublic();
        Assertions.assertFalse(isValidSignature(signedXml, fixedKeySelector(wrongKey)),
                "verification must fail against a public key that did not produce the signature");
    }

    private boolean isValidSignature(byte[] signedXml, KeySelector keySelector) throws Exception {
        SignatureValidator validator = new SignatureValidator();
        try (InputStream is = new ByteArrayInputStream(signedXml)) {
            DOMValidateContext vc = validator.getValidateContext(is, keySelector, false);
            updateIdReferences(vc, "SignedElement", "id");
            return validator.validate(vc);
        }
    }

    private static byte[] flipSignatureValueBit(byte[] signedXml) throws Exception {
        Document doc = XMLUtils.read(new ByteArrayInputStream(signedXml), false);
        NodeList nl = doc.getElementsByTagNameNS(Constants.SignatureSpecNS, Constants._TAG_SIGNATUREVALUE);
        Element sigValue = (Element) nl.item(0);
        byte[] sig = XMLUtils.decode(sigValue.getTextContent().trim());
        sig[sig.length / 2] ^= 0x01;
        sigValue.setTextContent(XMLUtils.encodeToString(sig));
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        XMLUtils.outputDOMc14nWithComments(doc, bos);
        return bos.toByteArray();
    }

    private static KeySelector fixedKeySelector(final PublicKey key) {
        return new KeySelector() {
            @Override
            public KeySelectorResult select(KeyInfo keyInfo, KeySelector.Purpose purpose,
                                            AlgorithmMethod method, XMLCryptoContext context) {
                return () -> key;
            }
        };
    }

    @Override
    KeyStore getKeyStore() {
        return keyStore;
    }

    @Override
    char[] getKeyPassword() {
        return MLDSA_KS_PASSWORD.toCharArray();
    }
}
