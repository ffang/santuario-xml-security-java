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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Base64;

import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;

import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.test.javax.xml.crypto.KeySelectors;
import org.apache.xml.security.testutils.SelfSignedCertGenerator;
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
import org.w3c.dom.Text;

/**
 * Tests for ML-DSA (FIPS 204) XML digital signatures via the
 * {@code javax.xml.crypto.dsig.XMLSignatureFactory} DOM API.
 *
 * <p>Key pairs and self-signed certificates are generated on the fly for each of
 * ML-DSA-44/65/87 via {@link SelfSignedCertGenerator}, rather than loading a
 * pre-generated keystore committed as a binary test resource (see SANTUARIO-634).
 * The test requires BouncyCastle on the runtime classpath to supply the ML-DSA
 * JCA provider; compile-time BC classes are deliberately avoided so the default
 * build (without {@code -P bouncycastle}) still compiles cleanly.
 *
 * <p>Run with the Maven {@code bouncycastle} profile:
 * <pre>mvn test -Dtest=XMLSignatureMLDSATest -P bouncycastle</pre>
 */
class XMLSignatureMLDSATest extends XMLSignatureAbstract {

    static final char[] KEY_PASSWORD = "security".toCharArray();

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
            keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, null);
            for (String alias : new String[]{"ml-dsa-44", "ml-dsa-65", "ml-dsa-87"}) {
                String jcaAlgorithm = alias.toUpperCase();
                KeyPairGenerator kpg = KeyPairGenerator.getInstance(jcaAlgorithm, "BC");
                KeyPair keyPair = kpg.generateKeyPair();
                X509Certificate cert = SelfSignedCertGenerator.generate(
                        keyPair, jcaAlgorithm, "CN=Test " + jcaAlgorithm + ",O=Apache Santuario,C=US", 365);
                keyStore.setKeyEntry(alias, keyPair.getPrivate(), KEY_PASSWORD, new Certificate[]{cert});
            }
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

        byte[] tamperedXml = flipByteInSignatureValue(signedXml);

        boolean coreValidity = validateSignatureWithJcpApi(tamperedXml, new KeySelectors.RawX509KeySelector());
        Assertions.assertFalse(coreValidity, "A tampered SignatureValue must not validate");
    }

    @ParameterizedTest
    @CsvSource({
        XMLSignature.ALGO_ID_SIGNATURE_MLDSA_44 + ",ml-dsa-44",
        XMLSignature.ALGO_ID_SIGNATURE_MLDSA_65 + ",ml-dsa-65",
        XMLSignature.ALGO_ID_SIGNATURE_MLDSA_87 + ",ml-dsa-87",
    })
    void testMLDSAWrongPublicKeyRejected(String signatureAlgorithmURI, String alias) throws Exception {
        Assumptions.assumeTrue(mlDsaAvailable, "ML-DSA requires BouncyCastle 1.81+");
        byte[] signedXml = doSignWithJcpApi(signatureAlgorithmURI, alias, false);

        KeyPairGenerator kpg = KeyPairGenerator.getInstance(alias.toUpperCase(), "BC");
        PublicKey wrongPublicKey = kpg.generateKeyPair().getPublic();

        KeySelector wrongKeySelector = new KeySelector() {
            @Override
            public KeySelectorResult select(KeyInfo keyInfo, Purpose purpose, AlgorithmMethod method,
                                             XMLCryptoContext context) throws KeySelectorException {
                return () -> wrongPublicKey;
            }
        };

        boolean coreValidity = validateSignatureWithJcpApi(signedXml, wrongKeySelector);
        Assertions.assertFalse(coreValidity, "Verification against the wrong public key must not validate");
    }

    /**
     * Decodes the &lt;SignatureValue&gt; text content, flips one byte, and re-serializes -
     * simulates an attacker (or transport bug) corrupting the signature bytes while leaving
     * the rest of the document, including the embedded certificate, intact.
     */
    private byte[] flipByteInSignatureValue(byte[] signedXml) throws Exception {
        Document doc;
        try (ByteArrayInputStream is = new ByteArrayInputStream(signedXml)) {
            doc = XMLUtils.read(is, false);
        }
        NodeList sigValues = doc.getElementsByTagNameNS(Constants.SignatureSpecNS, "SignatureValue");
        Assertions.assertEquals(1, sigValues.getLength(), "Expected exactly one SignatureValue element");
        Element sigValueElement = (Element) sigValues.item(0);

        byte[] sigBytes = Base64.getMimeDecoder().decode(sigValueElement.getTextContent());
        sigBytes[sigBytes.length / 2] ^= (byte) 0xFF;
        String tamperedBase64 = Base64.getEncoder().encodeToString(sigBytes);

        // Replace the SignatureValue element's text content in place
        NodeList children = sigValueElement.getChildNodes();
        for (int i = children.getLength() - 1; i >= 0; i--) {
            sigValueElement.removeChild(children.item(i));
        }
        Text newText = doc.createTextNode(tamperedBase64);
        sigValueElement.appendChild(newText);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        XMLUtils.outputDOMc14nWithComments(doc, bos);
        return bos.toByteArray();
    }

    @Override
    KeyStore getKeyStore() {
        return keyStore;
    }

    @Override
    char[] getKeyPassword() {
        return KEY_PASSWORD;
    }
}
