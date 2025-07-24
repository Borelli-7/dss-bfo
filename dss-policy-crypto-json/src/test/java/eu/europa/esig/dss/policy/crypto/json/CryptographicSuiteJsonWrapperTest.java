/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.policy.crypto.json;

import com.github.erosb.jsonsKema.JsonArray;
import com.github.erosb.jsonsKema.JsonNumber;
import com.github.erosb.jsonsKema.JsonObject;
import com.github.erosb.jsonsKema.JsonString;
import com.github.erosb.jsonsKema.JsonValue;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.policy.SignatureAlgorithmWithMinKeySize;
import eu.europa.esig.json.JsonObjectWrapper;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CryptographicSuiteJsonWrapperTest {

    private static final String MODULES_LENGTH = "moduluslength";
    private static final String PLENGTH = "plength";
    private static final String QLENGTH = "glength";

    @Test
    void getAcceptableDigestAlgorithmsTest() {
        Map<JsonString, JsonValue> securitySuitabilityPolicyMap = new HashMap<>();
        JsonObject jsonObject = new JsonObject(securitySuitabilityPolicyMap);

        CryptographicSuiteJsonWrapper cryptographicSuite = new CryptographicSuiteJsonWrapper(new JsonObjectWrapper(jsonObject));
        assertEquals(Collections.emptySet(), new HashSet<>(cryptographicSuite.getAcceptableDigestAlgorithms()));

        List<JsonValue> algorithmsList = new ArrayList<>();
        JsonArray algorithmsArray = new JsonArray(algorithmsList);
        securitySuitabilityPolicyMap.put(new JsonString("Algorithm"), algorithmsArray);

        cryptographicSuite = new CryptographicSuiteJsonWrapper(new JsonObjectWrapper(jsonObject));
        assertEquals(Collections.emptySet(), new HashSet<>(cryptographicSuite.getAcceptableDigestAlgorithms()));

        algorithmsList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA224, "2029-01-01"));

        cryptographicSuite = new CryptographicSuiteJsonWrapper(new JsonObjectWrapper(jsonObject));
        Set<DigestAlgorithm> expectedSet = new HashSet<>(Collections.singletonList(DigestAlgorithm.SHA224));
        assertEquals(expectedSet, new HashSet<>(cryptographicSuite.getAcceptableDigestAlgorithms()));

        algorithmsList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA256, null));

        cryptographicSuite = new CryptographicSuiteJsonWrapper(new JsonObjectWrapper(jsonObject));
        expectedSet = new HashSet<>(Arrays.asList(DigestAlgorithm.SHA224, DigestAlgorithm.SHA256));
        assertEquals(expectedSet, new HashSet<>(cryptographicSuite.getAcceptableDigestAlgorithms()));

        algorithmsList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA384, null));
        algorithmsList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA512, null));
        algorithmsList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA3_256, null));
        algorithmsList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA3_384, null));
        algorithmsList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA3_512, null));

        cryptographicSuite = new CryptographicSuiteJsonWrapper(new JsonObjectWrapper(jsonObject));

        expectedSet = new HashSet<>(Arrays.asList(
                DigestAlgorithm.SHA224, DigestAlgorithm.SHA256, DigestAlgorithm.SHA384, DigestAlgorithm.SHA512,
                DigestAlgorithm.SHA3_256, DigestAlgorithm.SHA3_384, DigestAlgorithm.SHA3_512));

        assertEquals(expectedSet, new HashSet<>(cryptographicSuite.getAcceptableDigestAlgorithms()));
    }

    @Test
    void getAcceptableDigestAlgorithmsWithEmptyListTest() {
        Map<JsonString, JsonValue> securitySuitabilityPolicyMap = new HashMap<>();
        securitySuitabilityPolicyMap.put(new JsonString("Algorithm"), new JsonArray(Collections.emptyList()));

        JsonObject jsonObject = new JsonObject(securitySuitabilityPolicyMap);
        CryptographicSuiteJsonWrapper cryptographicSuite = new CryptographicSuiteJsonWrapper(new JsonObjectWrapper(jsonObject));
        Map<DigestAlgorithm, Date> digestAlgorithmsWithExpirationDates = cryptographicSuite.getAcceptableDigestAlgorithmsWithExpirationDates();
        assertTrue(digestAlgorithmsWithExpirationDates.isEmpty());
    }

    @Test
    void getAcceptableDigestAlgorithmsWithInvalidDateTest() {
        List<JsonValue> algorithmsList = new ArrayList<>();
        algorithmsList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA256, "invalid-date"));

        JsonArray algorithmsArray = new JsonArray(algorithmsList);
        Map<JsonString, JsonValue> securitySuitabilityPolicyMap = new HashMap<>();
        securitySuitabilityPolicyMap.put(new JsonString("Algorithm"), algorithmsArray);
        JsonObject jsonObject = new JsonObject(securitySuitabilityPolicyMap);

        CryptographicSuiteJsonWrapper cryptographicSuite = new CryptographicSuiteJsonWrapper(new JsonObjectWrapper(jsonObject));

        Map<DigestAlgorithm, Date> digestAlgorithmsWithExpirationDates = cryptographicSuite.getAcceptableDigestAlgorithmsWithExpirationDates();
        assertTrue(digestAlgorithmsWithExpirationDates.isEmpty());
    }

    @Test
    void getAcceptableDigestAlgorithmsWithDuplicateAlgorithmsTest() {
        Map<JsonString, JsonValue> securitySuitabilityPolicyMap = new HashMap<>();

        securitySuitabilityPolicyMap.put(new JsonString("Algorithm"), new JsonArray(Arrays.asList(
                createDigestAlgorithmDefinition(DigestAlgorithm.SHA224, "2021-01-01")
        )));

        CryptographicSuiteJsonWrapper cryptographicSuite = new CryptographicSuiteJsonWrapper(new JsonObjectWrapper(new JsonObject(securitySuitabilityPolicyMap)));

        Calendar calendar = Calendar.getInstance();
        calendar.setTimeZone(TimeZone.getTimeZone("GMT+0"));
        calendar.clear();

        Map<DigestAlgorithm, Date> expected = new HashMap<>();

        calendar.set(2021, Calendar.JANUARY, 1);
        expected.put(DigestAlgorithm.SHA224, calendar.getTime());

        assertEquals(expected, cryptographicSuite.getAcceptableDigestAlgorithmsWithExpirationDates());

        // duplicate entries test

        securitySuitabilityPolicyMap = new HashMap<>();

        securitySuitabilityPolicyMap.put(new JsonString("Algorithm"), new JsonArray(Arrays.asList(
                createDigestAlgorithmDefinition(DigestAlgorithm.SHA224, "2021-01-01"),
                createDigestAlgorithmDefinition(DigestAlgorithm.SHA224, "2029-01-01")
        )));

        expected = new HashMap<>();

        calendar.set(2029, Calendar.JANUARY, 1);
        expected.put(DigestAlgorithm.SHA224, calendar.getTime());

        cryptographicSuite = new CryptographicSuiteJsonWrapper(new JsonObjectWrapper(new JsonObject(securitySuitabilityPolicyMap)));
        assertEquals(expected, cryptographicSuite.getAcceptableDigestAlgorithmsWithExpirationDates());

        // opposite test

        securitySuitabilityPolicyMap = new HashMap<>();

        securitySuitabilityPolicyMap.put(new JsonString("Algorithm"), new JsonArray(Arrays.asList(
                createDigestAlgorithmDefinition(DigestAlgorithm.SHA224, "2029-01-01"),
                createDigestAlgorithmDefinition(DigestAlgorithm.SHA224, "2021-01-01")
        )));

        cryptographicSuite = new CryptographicSuiteJsonWrapper(new JsonObjectWrapper(new JsonObject(securitySuitabilityPolicyMap)));
        assertEquals(expected, cryptographicSuite.getAcceptableDigestAlgorithmsWithExpirationDates());

        // null test

        securitySuitabilityPolicyMap = new HashMap<>();

        securitySuitabilityPolicyMap.put(new JsonString("Algorithm"), new JsonArray(Arrays.asList(
                createDigestAlgorithmDefinition(DigestAlgorithm.SHA224, "2021-01-01"),
                createDigestAlgorithmDefinition(DigestAlgorithm.SHA224, "2029-01-01"),
                createDigestAlgorithmDefinition(DigestAlgorithm.SHA224, null)
        )));

        expected = new HashMap<>();

        expected.put(DigestAlgorithm.SHA224, null);

        cryptographicSuite = new CryptographicSuiteJsonWrapper(new JsonObjectWrapper(new JsonObject(securitySuitabilityPolicyMap)));
        assertEquals(expected, cryptographicSuite.getAcceptableDigestAlgorithmsWithExpirationDates());

        // opposite null test

        securitySuitabilityPolicyMap = new HashMap<>();

        securitySuitabilityPolicyMap.put(new JsonString("Algorithm"), new JsonArray(Arrays.asList(
                createDigestAlgorithmDefinition(DigestAlgorithm.SHA224, null),
                createDigestAlgorithmDefinition(DigestAlgorithm.SHA224, "2021-01-01"),
                createDigestAlgorithmDefinition(DigestAlgorithm.SHA224, "2029-01-01")
        )));

        expected = new HashMap<>();

        expected.put(DigestAlgorithm.SHA224, null);

        cryptographicSuite = new CryptographicSuiteJsonWrapper(new JsonObjectWrapper(new JsonObject(securitySuitabilityPolicyMap)));
        assertEquals(expected, cryptographicSuite.getAcceptableDigestAlgorithmsWithExpirationDates());
    }

    @Test
    void getAcceptableDigestAlgorithmsWithUnknownAlgorithmTest() {
        List<JsonValue> algorithmsList = new ArrayList<>();
        HashMap<JsonString, JsonValue> algoMap = new HashMap<>();
        algoMap.put(new JsonString("Algorithm"), new JsonString("SHA999"));
        algoMap.put(new JsonString("ExpirationDate"), new JsonString("2030-12-31"));
        JsonObject unknownAlgorithm = new JsonObject(algoMap);
        algorithmsList.add(unknownAlgorithm);

        JsonArray algorithmsArray = new JsonArray(algorithmsList);
        Map<JsonString, JsonValue> securitySuitabilityPolicyMap = new HashMap<>();
        securitySuitabilityPolicyMap.put(new JsonString("Algorithm"), algorithmsArray);
        JsonObject jsonObject = new JsonObject(securitySuitabilityPolicyMap);

        CryptographicSuiteJsonWrapper cryptographicSuite = new CryptographicSuiteJsonWrapper(new JsonObjectWrapper(jsonObject));
        // silently skip unrecognized algorithms
        assertTrue(cryptographicSuite.getAcceptableDigestAlgorithmsWithExpirationDates().isEmpty());
    }

    @Test
    void getAcceptableDigestAlgorithmsWithExpirationDatesTest() {
        Map<JsonString, JsonValue> securitySuitabilityPolicyMap = new HashMap<>();

        List<JsonValue> algorithmsList = new ArrayList<>();
        algorithmsList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA224, "2029-01-01"));
        algorithmsList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA256, null));
        algorithmsList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA384, null));
        algorithmsList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA512, null));
        algorithmsList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA3_256, null));
        algorithmsList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA3_384, null));
        algorithmsList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA3_512, null));

        JsonArray algorithmsArray = new JsonArray(algorithmsList);
        securitySuitabilityPolicyMap.put(new JsonString("Algorithm"), algorithmsArray);
        JsonObject jsonObject = new JsonObject(securitySuitabilityPolicyMap);

        CryptographicSuiteJsonWrapper cryptographicSuite = new CryptographicSuiteJsonWrapper(new JsonObjectWrapper(jsonObject));
        Map<DigestAlgorithm, Date> digestAlgorithmsWithExpirationDates = cryptographicSuite.getAcceptableDigestAlgorithmsWithExpirationDates();

        Calendar calendar = Calendar.getInstance();
        calendar.setTimeZone(TimeZone.getTimeZone("UTC"));
        calendar.clear();

        Map<DigestAlgorithm, Date> expectedMap = new LinkedHashMap<>();

        calendar.set(2029, Calendar.JANUARY, 1);
        expectedMap.put(DigestAlgorithm.SHA224, calendar.getTime());

        expectedMap.put(DigestAlgorithm.SHA256, null);
        expectedMap.put(DigestAlgorithm.SHA384, null);
        expectedMap.put(DigestAlgorithm.SHA512, null);
        expectedMap.put(DigestAlgorithm.SHA3_256, null);
        expectedMap.put(DigestAlgorithm.SHA3_384, null);
        expectedMap.put(DigestAlgorithm.SHA3_512, null);

        assertEquals(expectedMap, new LinkedHashMap<>(digestAlgorithmsWithExpirationDates));
    }

    @Test
    void getAcceptableSignatureAlgorithmsEmptyList() {
        Map<JsonString, JsonValue> securitySuitabilityPolicyMap = new HashMap<>();
        securitySuitabilityPolicyMap.put(new JsonString("Algorithm"), new JsonArray(Collections.emptyList()));

        CryptographicSuiteJsonWrapper cryptographicSuite = new CryptographicSuiteJsonWrapper(
                new JsonObjectWrapper(new JsonObject(securitySuitabilityPolicyMap))
        );

        List<SignatureAlgorithm> algorithms = cryptographicSuite.getAcceptableSignatureAlgorithms();
        assertTrue(algorithms.isEmpty(), "Expected no encryption algorithms for empty list.");
    }

    @Test
    void getAcceptableSignatureAlgorithmsUnknownAlgorithmIgnored() {
        List<JsonValue> algorithmsList = new ArrayList<>();
        HashMap<JsonString, JsonValue> algoMap = new HashMap<>();
        algoMap.put(new JsonString("Algorithm"), new JsonString("UNKNOWN_ALGO"));
        algoMap.put(new JsonString("Evaluations"), new JsonArray(Collections.emptyList()));
        JsonObject unknownAlgorithm = new JsonObject(algoMap);
        algorithmsList.add(unknownAlgorithm);

        Map<JsonString, JsonValue> policyMap = new HashMap<>();
        policyMap.put(new JsonString("Algorithm"), new JsonArray(algorithmsList));

        CryptographicSuiteJsonWrapper cryptographicSuite = new CryptographicSuiteJsonWrapper(
                new JsonObjectWrapper(new JsonObject(policyMap))
        );

        List<SignatureAlgorithm> algorithms = cryptographicSuite.getAcceptableSignatureAlgorithms();
        assertTrue(algorithms.isEmpty(), "Unknown algorithm should be ignored or not parsed.");
    }

    @Test
    void getAcceptableSignatureAlgorithmsTest() {
        Map<JsonString, JsonValue> securitySuitabilityPolicyMap = new HashMap<>();

        List<JsonValue> algorithmsList = new ArrayList<>();
        algorithmsList.add(createEncryptionAlgorithmDefinition(EncryptionAlgorithm.DSA, Arrays.asList(
                new EvaluationType("2029-01-01", Arrays.asList(
                        new ParameterType(1900, PLENGTH),
                        new ParameterType(200, QLENGTH)
                )),
                new EvaluationType(null, Arrays.asList(
                        new ParameterType(3000, PLENGTH),
                        new ParameterType(250, QLENGTH)
                )))
        ));
        algorithmsList.add(createSignatureAlgorithmDefinition(SignatureAlgorithm.ECDSA_SHA224, Collections.singletonList(
                        new EvaluationType("2029-01-01", Collections.emptyList())
                )
        ));
        algorithmsList.add(createSignatureAlgorithmDefinition(SignatureAlgorithm.ECDSA_SHA256, Collections.emptyList()));
        algorithmsList.add(createSignatureAlgorithmDefinition(SignatureAlgorithm.RSA_SHA224, Arrays.asList(
                new EvaluationType("2029-01-01", Collections.singletonList(
                        new ParameterType(1900, MODULES_LENGTH)
                )),
                new EvaluationType("2029-01-01", Collections.singletonList(
                        new ParameterType(3000, MODULES_LENGTH)
                )))
        ));
        algorithmsList.add(createEncryptionAlgorithmDefinition(EncryptionAlgorithm.RSASSA_PSS, Arrays.asList(
                new EvaluationType("2029-01-01", Collections.singletonList(
                        new ParameterType(1900, MODULES_LENGTH)
                )),
                new EvaluationType("2029-01-01", Collections.singletonList(
                        new ParameterType(3000, MODULES_LENGTH)
                )))
        ));

        JsonArray algorithmsArray = new JsonArray(algorithmsList);
        securitySuitabilityPolicyMap.put(new JsonString("Algorithm"), algorithmsArray);
        JsonObject jsonObject = new JsonObject(securitySuitabilityPolicyMap);

        CryptographicSuiteJsonWrapper cryptographicSuite = new CryptographicSuiteJsonWrapper(new JsonObjectWrapper(jsonObject));

        Set<SignatureAlgorithm> expected = new HashSet<>(Arrays.asList(SignatureAlgorithm.ECDSA_SHA224,
                SignatureAlgorithm.ECDSA_SHA256, SignatureAlgorithm.RSA_SHA224));
        assertEquals(expected, new HashSet<>(cryptographicSuite.getAcceptableSignatureAlgorithms()));

        // Add DigestAlgorithm definition
        algorithmsList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA512, "2029-01-01"));

        cryptographicSuite = new CryptographicSuiteJsonWrapper(new JsonObjectWrapper(jsonObject));

        expected = new HashSet<>(Arrays.asList(SignatureAlgorithm.ECDSA_SHA224, SignatureAlgorithm.ECDSA_SHA256,
                SignatureAlgorithm.RSA_SHA224, SignatureAlgorithm.DSA_SHA512, SignatureAlgorithm.RSA_SSA_PSS_SHA512_MGF1));
        assertEquals(expected, new HashSet<>(cryptographicSuite.getAcceptableSignatureAlgorithms()));
    }

    @Test
    void getAcceptableSignatureAlgorithmsWithMinKeySizesDuplicatesHandledCorrectly() {
        List<JsonValue> algorithmsList = new ArrayList<>();

        // Duplicate entries for same algorithm
        algorithmsList.add(createEncryptionAlgorithmDefinition(EncryptionAlgorithm.DSA, Collections.singletonList(
                new EvaluationType("2029-01-01", Collections.singletonList(new ParameterType(1024, PLENGTH)))
        )));
        algorithmsList.add(createEncryptionAlgorithmDefinition(EncryptionAlgorithm.DSA, Collections.singletonList(
                new EvaluationType(null, Collections.singletonList(new ParameterType(2048, PLENGTH)))
        )));

        JsonArray algorithmsArray = new JsonArray(algorithmsList);
        Map<JsonString, JsonValue> policyMap = new HashMap<>();
        policyMap.put(new JsonString("Algorithm"), algorithmsArray);

        CryptographicSuiteJsonWrapper cryptographicSuite = new CryptographicSuiteJsonWrapper(
                new JsonObjectWrapper(new JsonObject(policyMap))
        );

        Set<SignatureAlgorithmWithMinKeySize> expected = Collections.emptySet();
        assertEquals(expected, new HashSet<>(cryptographicSuite.getAcceptableSignatureAlgorithmsWithMinKeySizes()));

        // Add DigestAlgorithm definition
        algorithmsList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA256, "2029-01-01"));
        algorithmsList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA512, "2029-01-01"));

        cryptographicSuite = new CryptographicSuiteJsonWrapper(
                new JsonObjectWrapper(new JsonObject(policyMap))
        );

        expected = new HashSet<>(Arrays.asList(
                new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.DSA_SHA256, 1024),
                new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.DSA_SHA512, 1024)
        ));
        assertEquals(expected, new HashSet<>(cryptographicSuite.getAcceptableSignatureAlgorithmsWithMinKeySizes()));
    }

    @Test
    void getAcceptableSignatureAlgorithmsWithMinKeySizesMissingParameter() {
        List<JsonValue> algorithmsList = new ArrayList<>();
        algorithmsList.add(new JsonString("DSA"));

        JsonArray algorithmsArray = new JsonArray(algorithmsList);

        algorithmsList.add(createEncryptionAlgorithmDefinition(EncryptionAlgorithm.DSA, Collections.emptyList()));

        HashMap<JsonString, JsonValue> paramMap = new HashMap<>();
        paramMap.put(new JsonString("Type"), new JsonString("pLength"));
        // Missing actual value
        JsonObject badParam = new JsonObject(paramMap);

        HashMap<JsonString, JsonValue> algoMap = new HashMap<>();
        algoMap.put(new JsonString("Algorithm"), algorithmsArray);

        HashMap<JsonString, JsonValue> evaluationMap = new HashMap<>();
        evaluationMap.put(new JsonString("ExpirationDate"), new JsonString("2029-01-01"));
        evaluationMap.put(new JsonString("Parameters"), new JsonArray(Collections.singletonList(badParam)));
        algoMap.put(new JsonString("Evaluations"), new JsonArray(Collections.singletonList(new JsonObject(evaluationMap))));

        Map<JsonString, JsonValue> policyMap = new HashMap<>();
        policyMap.put(new JsonString("Algorithm"), new JsonArray(Collections.singletonList(new JsonObject(algoMap))));

        // Add DigestAlgorithm definition
        algorithmsList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA256, "2029-01-01"));

        CryptographicSuiteJsonWrapper cryptographicSuite = new CryptographicSuiteJsonWrapper(
                new JsonObjectWrapper(new JsonObject(policyMap)));

        List<SignatureAlgorithmWithMinKeySize> result = cryptographicSuite.getAcceptableSignatureAlgorithmsWithMinKeySizes();
        assertTrue(result.isEmpty(), "Malformed parameter should result in exclusion.");
    }

    @Test
    void getAcceptableSignatureAlgorithmsWithMinKeySizesTest() {
        Map<JsonString, JsonValue> securitySuitabilityPolicyMap = new HashMap<>();

        List<JsonValue> algorithmsList = new ArrayList<>();
        algorithmsList.add(createEncryptionAlgorithmDefinition(EncryptionAlgorithm.DSA, Arrays.asList(
                new EvaluationType("2029-01-01", Arrays.asList(
                        new ParameterType(1900, PLENGTH),
                        new ParameterType(200, QLENGTH)
                )),
                new EvaluationType(null, Arrays.asList(
                        new ParameterType(3000, PLENGTH),
                        new ParameterType(250, QLENGTH)
                )))
        ));
        algorithmsList.add(createSignatureAlgorithmDefinition(SignatureAlgorithm.ECDSA_SHA224, Collections.singletonList(
                        new EvaluationType("2029-01-01", Collections.emptyList())
                )
        ));
        algorithmsList.add(createSignatureAlgorithmDefinition(SignatureAlgorithm.ECDSA_SHA256, Collections.emptyList()));
        algorithmsList.add(createSignatureAlgorithmDefinition(SignatureAlgorithm.RSA_SHA224, Arrays.asList(
                new EvaluationType("2029-01-01", Collections.singletonList(
                        new ParameterType(1900, MODULES_LENGTH)
                )),
                new EvaluationType("2029-01-01", Collections.singletonList(
                        new ParameterType(3000, MODULES_LENGTH)
                )))
        ));
        algorithmsList.add(createEncryptionAlgorithmDefinition(EncryptionAlgorithm.RSASSA_PSS, Arrays.asList(
                new EvaluationType("2029-01-01", Collections.singletonList(
                        new ParameterType(1900, MODULES_LENGTH)
                )),
                new EvaluationType("2029-01-01", Collections.singletonList(
                        new ParameterType(3000, MODULES_LENGTH)
                )))
        ));

        JsonArray algorithmsArray = new JsonArray(algorithmsList);
        securitySuitabilityPolicyMap.put(new JsonString("Algorithm"), algorithmsArray);
        JsonObject jsonObject = new JsonObject(securitySuitabilityPolicyMap);

        CryptographicSuiteJsonWrapper cryptographicSuite = new CryptographicSuiteJsonWrapper(new JsonObjectWrapper(jsonObject));

        Set<SignatureAlgorithmWithMinKeySize> expected = new HashSet<>(Arrays.asList(
                new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA224, 0),
                new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA256, 0),
                new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA224, 1900)
        ));
        assertEquals(expected, new HashSet<>(cryptographicSuite.getAcceptableSignatureAlgorithmsWithMinKeySizes()));

        // Add DigestAlgorithm definition
        algorithmsList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA512, "2029-01-01"));

        cryptographicSuite = new CryptographicSuiteJsonWrapper(new JsonObjectWrapper(jsonObject));

        expected = new HashSet<>(Arrays.asList(
                new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.DSA_SHA512, 1900),
                new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA224, 0),
                new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA256, 0),
                new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA224, 1900),
                new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SSA_PSS_SHA512_MGF1, 1900)
        ));

        assertEquals(expected, new HashSet<>(cryptographicSuite.getAcceptableSignatureAlgorithmsWithMinKeySizes()));
    }

    @Test
    void getAcceptableSignatureAlgorithmsWithExpirationDatesInvalidAndValidDateMixed() {
        List<JsonValue> algorithmsList = new ArrayList<>();

        algorithmsList.add(createEncryptionAlgorithmDefinition(EncryptionAlgorithm.DSA, Arrays.asList(
                new EvaluationType("invalid-date", Collections.singletonList(new ParameterType(1024, PLENGTH))),
                new EvaluationType("2035-12-31", Collections.singletonList(new ParameterType(2048, PLENGTH)))
        )));

        JsonArray algorithmsArray = new JsonArray(algorithmsList);
        Map<JsonString, JsonValue> policyMap = new HashMap<>();
        policyMap.put(new JsonString("Algorithm"), algorithmsArray);

        CryptographicSuiteJsonWrapper cryptographicSuite = new CryptographicSuiteJsonWrapper(
                new JsonObjectWrapper(new JsonObject(policyMap))
        );

        Map<SignatureAlgorithmWithMinKeySize, Date> result = cryptographicSuite.getAcceptableSignatureAlgorithmsWithExpirationDates();

        Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
        cal.clear();
        cal.set(2035, Calendar.DECEMBER, 31);

        assertEquals(Collections.emptyMap(), result);
    }

    @Test
    void getAcceptableSignatureAlgorithmsWithExpirationDatesTest() {
        Map<JsonString, JsonValue> securitySuitabilityPolicyMap = new HashMap<>();

        List<JsonValue> algorithmsList = new ArrayList<>();
        algorithmsList.add(createEncryptionAlgorithmDefinition(EncryptionAlgorithm.DSA, Arrays.asList(
                new EvaluationType("2029-01-01", Arrays.asList(
                        new ParameterType(1900, PLENGTH),
                        new ParameterType(200, QLENGTH)
                )),
                new EvaluationType(null, Arrays.asList(
                        new ParameterType(3000, PLENGTH),
                        new ParameterType(250, QLENGTH)
                )))
        ));
        algorithmsList.add(createSignatureAlgorithmDefinition(SignatureAlgorithm.ECDSA_SHA224, Collections.singletonList(
                        new EvaluationType("2029-01-01", Collections.emptyList())
                )
        ));
        algorithmsList.add(createSignatureAlgorithmDefinition(SignatureAlgorithm.ECDSA_SHA256, Collections.emptyList()));
        algorithmsList.add(createSignatureAlgorithmDefinition(SignatureAlgorithm.RSA_SHA224, Arrays.asList(
                new EvaluationType("2029-01-01", Collections.singletonList(
                        new ParameterType(1900, MODULES_LENGTH)
                )),
                new EvaluationType("2029-01-01", Collections.singletonList(
                        new ParameterType(3000, MODULES_LENGTH)
                )))
        ));
        algorithmsList.add(createEncryptionAlgorithmDefinition(EncryptionAlgorithm.RSASSA_PSS, Arrays.asList(
                new EvaluationType("2029-01-01", Collections.singletonList(
                        new ParameterType(1900, MODULES_LENGTH)
                )),
                new EvaluationType("2029-01-01", Collections.singletonList(
                        new ParameterType(3000, MODULES_LENGTH)
                )))
        ));

        JsonArray algorithmsArray = new JsonArray(algorithmsList);
        securitySuitabilityPolicyMap.put(new JsonString("Algorithm"), algorithmsArray);
        JsonObject jsonObject = new JsonObject(securitySuitabilityPolicyMap);

        CryptographicSuiteJsonWrapper cryptographicSuite = new CryptographicSuiteJsonWrapper(new JsonObjectWrapper(jsonObject));

        Calendar cal = Calendar.getInstance();
        cal.setTimeZone(TimeZone.getTimeZone("UTC"));
        cal.clear();

        Map<SignatureAlgorithmWithMinKeySize, Date> expected = new HashMap<>();

        cal.set(2029, Calendar.JANUARY, 1);
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA224, 1900), cal.getTime());
        cal.set(2029, Calendar.JANUARY, 1);
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA224, 3000), cal.getTime());
        cal.set(2029, Calendar.JANUARY, 1);
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA224, 0), cal.getTime());

        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA256, 0), null);

        assertEquals(expected, new HashMap<>(cryptographicSuite.getAcceptableSignatureAlgorithmsWithExpirationDates()));

        // Add DigestAlgorithm definition
        algorithmsList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA512, "2029-01-01"));

        cryptographicSuite = new CryptographicSuiteJsonWrapper(new JsonObjectWrapper(jsonObject));

        expected = new HashMap<>();

        cal.set(2029, Calendar.JANUARY, 1);
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA224, 1900), cal.getTime());
        cal.set(2029, Calendar.JANUARY, 1);
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA224, 3000), cal.getTime());
        cal.set(2029, Calendar.JANUARY, 1);
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA224, 0), cal.getTime());

        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA256, 0), null);

        cal.set(2029, Calendar.JANUARY, 1);
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.DSA_SHA512, 1900), cal.getTime());
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.DSA_SHA512, 3000), cal.getTime());

        cal.set(2029, Calendar.JANUARY, 1);
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SSA_PSS_SHA512_MGF1, 1900), cal.getTime());
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SSA_PSS_SHA512_MGF1, 3000), cal.getTime());

        assertEquals(expected, new HashMap<>(cryptographicSuite.getAcceptableSignatureAlgorithmsWithExpirationDates()));
    }

    @Test
    void dss3655RsaTest() {
        Map<JsonString, JsonValue> securitySuitabilityPolicyMap = new HashMap<>();

        securitySuitabilityPolicyMap.put(new JsonString("Algorithm"), new JsonArray(Arrays.asList(
                createSignatureAlgorithmDefinition(SignatureAlgorithm.RSA_SHA224, Arrays.asList(
                        new EvaluationType("2010-08-01", Arrays.asList(new ParameterType(786, MODULES_LENGTH))),
                        new EvaluationType("2019-10-01", Arrays.asList(new ParameterType(1024, MODULES_LENGTH))),
                        new EvaluationType("2019-10-01", Arrays.asList(new ParameterType(1536, MODULES_LENGTH))),
                        new EvaluationType("2029-01-01", Arrays.asList(new ParameterType(1900, MODULES_LENGTH))),
                        new EvaluationType("2029-01-01", Arrays.asList(new ParameterType(3000, MODULES_LENGTH)))
                )),
                createEncryptionAlgorithmDefinition(EncryptionAlgorithm.RSA, Arrays.asList(
                        new EvaluationType("2010-08-01", Arrays.asList(new ParameterType(786, MODULES_LENGTH))),
                        new EvaluationType("2019-10-01", Arrays.asList(new ParameterType(1024, MODULES_LENGTH))),
                        new EvaluationType("2019-10-01", Arrays.asList(new ParameterType(1536, MODULES_LENGTH))),
                        new EvaluationType("2025-01-01", Arrays.asList(new ParameterType(3000, MODULES_LENGTH))),
                        new EvaluationType(null, Arrays.asList(new ParameterType(4096, MODULES_LENGTH)))
                )))
        ));

        CryptographicSuiteJsonWrapper cryptographicSuite = new CryptographicSuiteJsonWrapper(new JsonObjectWrapper(new JsonObject(securitySuitabilityPolicyMap)));

        Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("GMT+0"));
        cal.clear();
        Map<SignatureAlgorithmWithMinKeySize, Date> expected = new HashMap<>();

        cal.set(2010, Calendar.AUGUST, 1);
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA224, 786), cal.getTime());
        cal.set(2019, Calendar.OCTOBER, 1);
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA224, 1024), cal.getTime());
        cal.set(2019, Calendar.OCTOBER, 1);
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA224, 1536), cal.getTime());
        cal.set(2029, Calendar.JANUARY, 1);
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA224, 1900), cal.getTime());
        cal.set(2029, Calendar.JANUARY, 1);
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA224, 3000), cal.getTime());

        assertEquals(expected, new HashMap<>(cryptographicSuite.getAcceptableSignatureAlgorithmsWithExpirationDates()));

        // Opposite order test

        securitySuitabilityPolicyMap = new HashMap<>();

        securitySuitabilityPolicyMap.put(new JsonString("Algorithm"), new JsonArray(Arrays.asList(
                createSignatureAlgorithmDefinition(SignatureAlgorithm.RSA_SHA224, Arrays.asList(
                        new EvaluationType("2010-08-01", Arrays.asList(new ParameterType(786, MODULES_LENGTH))),
                        new EvaluationType("2019-10-01", Arrays.asList(new ParameterType(1024, MODULES_LENGTH))),
                        new EvaluationType("2019-10-01", Arrays.asList(new ParameterType(1536, MODULES_LENGTH))),
                        new EvaluationType("2029-01-01", Arrays.asList(new ParameterType(1900, MODULES_LENGTH))),
                        new EvaluationType("2029-01-01", Arrays.asList(new ParameterType(3000, MODULES_LENGTH)))
                )),
                createEncryptionAlgorithmDefinition(EncryptionAlgorithm.RSA, Arrays.asList(
                        new EvaluationType("2010-08-01", Arrays.asList(new ParameterType(786, MODULES_LENGTH))),
                        new EvaluationType("2019-10-01", Arrays.asList(new ParameterType(1024, MODULES_LENGTH))),
                        new EvaluationType("2019-10-01", Arrays.asList(new ParameterType(1536, MODULES_LENGTH))),
                        new EvaluationType("2025-01-01", Arrays.asList(new ParameterType(3000, MODULES_LENGTH))),
                        new EvaluationType(null, Arrays.asList(new ParameterType(4096, MODULES_LENGTH)))
                )))
        ));

        cryptographicSuite = new CryptographicSuiteJsonWrapper(new JsonObjectWrapper(new JsonObject(securitySuitabilityPolicyMap)));
        assertEquals(expected, cryptographicSuite.getAcceptableSignatureAlgorithmsWithExpirationDates());

        // add Digest Algo test

        securitySuitabilityPolicyMap = new HashMap<>();

        securitySuitabilityPolicyMap.put(new JsonString("Algorithm"), new JsonArray(Arrays.asList(
                createSignatureAlgorithmDefinition(SignatureAlgorithm.RSA_SHA224, Arrays.asList(
                        new EvaluationType("2010-08-01", Arrays.asList(new ParameterType(786, MODULES_LENGTH))),
                        new EvaluationType("2019-10-01", Arrays.asList(new ParameterType(1024, MODULES_LENGTH))),
                        new EvaluationType("2019-10-01", Arrays.asList(new ParameterType(1536, MODULES_LENGTH))),
                        new EvaluationType("2029-01-01", Arrays.asList(new ParameterType(1900, MODULES_LENGTH))),
                        new EvaluationType("2029-01-01", Arrays.asList(new ParameterType(3000, MODULES_LENGTH)))
                )),
                createEncryptionAlgorithmDefinition(EncryptionAlgorithm.RSA, Arrays.asList(
                        new EvaluationType("2010-08-01", Arrays.asList(new ParameterType(786, MODULES_LENGTH))),
                        new EvaluationType("2019-10-01", Arrays.asList(new ParameterType(1024, MODULES_LENGTH))),
                        new EvaluationType("2019-10-01", Arrays.asList(new ParameterType(1536, MODULES_LENGTH))),
                        new EvaluationType("2025-01-01", Arrays.asList(new ParameterType(3000, MODULES_LENGTH))),
                        new EvaluationType(null, Arrays.asList(new ParameterType(4096, MODULES_LENGTH)))
                )),
                createDigestAlgorithmDefinition(DigestAlgorithm.SHA256, null)
        )));

        expected = new HashMap<>();

        cal.set(2010, Calendar.AUGUST, 1);
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA224, 786), cal.getTime());
        cal.set(2019, Calendar.OCTOBER, 1);
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA224, 1024), cal.getTime());
        cal.set(2019, Calendar.OCTOBER, 1);
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA224, 1536), cal.getTime());
        cal.set(2029, Calendar.JANUARY, 1);
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA224, 1900), cal.getTime());
        cal.set(2029, Calendar.JANUARY, 1);
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA224, 3000), cal.getTime());

        cal.set(2010, Calendar.AUGUST, 1);
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA256, 786), cal.getTime());
        cal.set(2019, Calendar.OCTOBER, 1);
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA256, 1024), cal.getTime());
        cal.set(2019, Calendar.OCTOBER, 1);
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA256, 1536), cal.getTime());
        cal.set(2025, Calendar.JANUARY, 1);
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA256, 3000), cal.getTime());

        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA256, 4096), null);

        cryptographicSuite = new CryptographicSuiteJsonWrapper(new JsonObjectWrapper(new JsonObject(securitySuitabilityPolicyMap)));
        assertEquals(expected, new HashMap<>(cryptographicSuite.getAcceptableSignatureAlgorithmsWithExpirationDates()));

        // opposite test

        securitySuitabilityPolicyMap = new HashMap<>();

        securitySuitabilityPolicyMap.put(new JsonString("Algorithm"), new JsonArray(Arrays.asList(
                createDigestAlgorithmDefinition(DigestAlgorithm.SHA256, null),
                createSignatureAlgorithmDefinition(SignatureAlgorithm.RSA_SHA224, Arrays.asList(
                        new EvaluationType("2010-08-01", Arrays.asList(new ParameterType(786, MODULES_LENGTH))),
                        new EvaluationType("2019-10-01", Arrays.asList(new ParameterType(1024, MODULES_LENGTH))),
                        new EvaluationType("2019-10-01", Arrays.asList(new ParameterType(1536, MODULES_LENGTH))),
                        new EvaluationType("2029-01-01", Arrays.asList(new ParameterType(1900, MODULES_LENGTH))),
                        new EvaluationType("2029-01-01", Arrays.asList(new ParameterType(3000, MODULES_LENGTH)))
                )),
                createEncryptionAlgorithmDefinition(EncryptionAlgorithm.RSA, Arrays.asList(
                        new EvaluationType("2010-08-01", Arrays.asList(new ParameterType(786, MODULES_LENGTH))),
                        new EvaluationType("2019-10-01", Arrays.asList(new ParameterType(1024, MODULES_LENGTH))),
                        new EvaluationType("2019-10-01", Arrays.asList(new ParameterType(1536, MODULES_LENGTH))),
                        new EvaluationType("2025-01-01", Arrays.asList(new ParameterType(3000, MODULES_LENGTH))),
                        new EvaluationType(null, Arrays.asList(new ParameterType(4096, MODULES_LENGTH)))
                ))
        )));

        cryptographicSuite = new CryptographicSuiteJsonWrapper(new JsonObjectWrapper(new JsonObject(securitySuitabilityPolicyMap)));
        assertEquals(expected, new HashMap<>(cryptographicSuite.getAcceptableSignatureAlgorithmsWithExpirationDates()));

        // DigestAlgo expiration after test

        securitySuitabilityPolicyMap = new HashMap<>();

        securitySuitabilityPolicyMap.put(new JsonString("Algorithm"), new JsonArray(Arrays.asList(
                createSignatureAlgorithmDefinition(SignatureAlgorithm.RSA_SHA224, Arrays.asList(
                        new EvaluationType("2010-08-01", Arrays.asList(new ParameterType(786, MODULES_LENGTH))),
                        new EvaluationType("2019-10-01", Arrays.asList(new ParameterType(1024, MODULES_LENGTH))),
                        new EvaluationType("2019-10-01", Arrays.asList(new ParameterType(1536, MODULES_LENGTH))),
                        new EvaluationType("2029-01-01", Arrays.asList(new ParameterType(1900, MODULES_LENGTH))),
                        new EvaluationType("2029-01-01", Arrays.asList(new ParameterType(3000, MODULES_LENGTH)))
                )),
                createEncryptionAlgorithmDefinition(EncryptionAlgorithm.RSA, Arrays.asList(
                        new EvaluationType("2010-08-01", Arrays.asList(new ParameterType(786, MODULES_LENGTH))),
                        new EvaluationType("2019-10-01", Arrays.asList(new ParameterType(1024, MODULES_LENGTH))),
                        new EvaluationType("2019-10-01", Arrays.asList(new ParameterType(1536, MODULES_LENGTH))),
                        new EvaluationType("2025-01-01", Arrays.asList(new ParameterType(3000, MODULES_LENGTH))),
                        new EvaluationType(null, Arrays.asList(new ParameterType(4096, MODULES_LENGTH)))
                )),
                createDigestAlgorithmDefinition(DigestAlgorithm.SHA256, "2029-01-01+00:00")
        )));

        expected = new HashMap<>();

        cal.set(2010, Calendar.AUGUST, 1);
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA224, 786), cal.getTime());
        cal.set(2019, Calendar.OCTOBER, 1);
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA224, 1024), cal.getTime());
        cal.set(2019, Calendar.OCTOBER, 1);
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA224, 1536), cal.getTime());
        cal.set(2029, Calendar.JANUARY, 1);
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA224, 1900), cal.getTime());
        cal.set(2029, Calendar.JANUARY, 1);
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA224, 3000), cal.getTime());

        cal.set(2010, Calendar.AUGUST, 1);
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA256, 786), cal.getTime());
        cal.set(2019, Calendar.OCTOBER, 1);
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA256, 1024), cal.getTime());
        cal.set(2019, Calendar.OCTOBER, 1);
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA256, 1536), cal.getTime());
        cal.set(2025, Calendar.JANUARY, 1);
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA256, 3000), cal.getTime());
        cal.set(2029, Calendar.JANUARY, 1);
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA256, 4096), cal.getTime());

        cryptographicSuite = new CryptographicSuiteJsonWrapper(new JsonObjectWrapper(new JsonObject(securitySuitabilityPolicyMap)));
        assertEquals(expected, new HashMap<>(cryptographicSuite.getAcceptableSignatureAlgorithmsWithExpirationDates()));

        // opposite test

        securitySuitabilityPolicyMap = new HashMap<>();

        securitySuitabilityPolicyMap.put(new JsonString("Algorithm"), new JsonArray(Arrays.asList(
                createDigestAlgorithmDefinition(DigestAlgorithm.SHA256, "2029-01-01+00:00"),
                createSignatureAlgorithmDefinition(SignatureAlgorithm.RSA_SHA224, Arrays.asList(
                        new EvaluationType("2010-08-01", Arrays.asList(new ParameterType(786, MODULES_LENGTH))),
                        new EvaluationType("2019-10-01", Arrays.asList(new ParameterType(1024, MODULES_LENGTH))),
                        new EvaluationType("2019-10-01", Arrays.asList(new ParameterType(1536, MODULES_LENGTH))),
                        new EvaluationType("2029-01-01", Arrays.asList(new ParameterType(1900, MODULES_LENGTH))),
                        new EvaluationType("2029-01-01", Arrays.asList(new ParameterType(3000, MODULES_LENGTH)))
                )),
                createEncryptionAlgorithmDefinition(EncryptionAlgorithm.RSA, Arrays.asList(
                        new EvaluationType("2010-08-01", Arrays.asList(new ParameterType(786, MODULES_LENGTH))),
                        new EvaluationType("2019-10-01", Arrays.asList(new ParameterType(1024, MODULES_LENGTH))),
                        new EvaluationType("2019-10-01", Arrays.asList(new ParameterType(1536, MODULES_LENGTH))),
                        new EvaluationType("2025-01-01", Arrays.asList(new ParameterType(3000, MODULES_LENGTH))),
                        new EvaluationType(null, Arrays.asList(new ParameterType(4096, MODULES_LENGTH)))
                ))
        )));

        cryptographicSuite = new CryptographicSuiteJsonWrapper(new JsonObjectWrapper(new JsonObject(securitySuitabilityPolicyMap)));
        assertEquals(expected, new HashMap<>(cryptographicSuite.getAcceptableSignatureAlgorithmsWithExpirationDates()));

        // DigestAlgo expiration before

        securitySuitabilityPolicyMap = new HashMap<>();

        securitySuitabilityPolicyMap.put(new JsonString("Algorithm"), new JsonArray(Arrays.asList(
                createSignatureAlgorithmDefinition(SignatureAlgorithm.RSA_SHA224, Arrays.asList(
                        new EvaluationType("2010-08-01", Arrays.asList(new ParameterType(786, MODULES_LENGTH))),
                        new EvaluationType("2019-10-01", Arrays.asList(new ParameterType(1024, MODULES_LENGTH))),
                        new EvaluationType("2019-10-01", Arrays.asList(new ParameterType(1536, MODULES_LENGTH))),
                        new EvaluationType("2029-01-01", Arrays.asList(new ParameterType(1900, MODULES_LENGTH))),
                        new EvaluationType("2029-01-01", Arrays.asList(new ParameterType(3000, MODULES_LENGTH)))
                )),
                createEncryptionAlgorithmDefinition(EncryptionAlgorithm.RSA, Arrays.asList(
                        new EvaluationType("2010-08-01", Arrays.asList(new ParameterType(786, MODULES_LENGTH))),
                        new EvaluationType("2019-10-01", Arrays.asList(new ParameterType(1024, MODULES_LENGTH))),
                        new EvaluationType("2019-10-01", Arrays.asList(new ParameterType(1536, MODULES_LENGTH))),
                        new EvaluationType("2025-01-01", Arrays.asList(new ParameterType(3000, MODULES_LENGTH))),
                        new EvaluationType(null, Arrays.asList(new ParameterType(4096, MODULES_LENGTH)))
                )),
                createDigestAlgorithmDefinition(DigestAlgorithm.SHA256, "2019-01-01+00:00")
        )));

        expected = new HashMap<>();

        cal.set(2010, Calendar.AUGUST, 1);
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA224, 786), cal.getTime());
        cal.set(2019, Calendar.OCTOBER, 1);
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA224, 1024), cal.getTime());
        cal.set(2019, Calendar.OCTOBER, 1);
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA224, 1536), cal.getTime());
        cal.set(2029, Calendar.JANUARY, 1);
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA224, 1900), cal.getTime());
        cal.set(2029, Calendar.JANUARY, 1);
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA224, 3000), cal.getTime());

        cal.set(2010, Calendar.AUGUST, 1);
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA256, 786), cal.getTime());
        cal.set(2019, Calendar.JANUARY, 1);
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA256, 1024), cal.getTime());
        cal.set(2019, Calendar.JANUARY, 1);
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA256, 1536), cal.getTime());
        cal.set(2019, Calendar.JANUARY, 1);
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA256, 3000), cal.getTime());
        cal.set(2019, Calendar.JANUARY, 1);
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA256, 4096), cal.getTime());

        cryptographicSuite = new CryptographicSuiteJsonWrapper(new JsonObjectWrapper(new JsonObject(securitySuitabilityPolicyMap)));
        assertEquals(expected, new HashMap<>(cryptographicSuite.getAcceptableSignatureAlgorithmsWithExpirationDates()));

        // opposite test

        securitySuitabilityPolicyMap = new HashMap<>();

        securitySuitabilityPolicyMap.put(new JsonString("Algorithm"), new JsonArray(Arrays.asList(
                createDigestAlgorithmDefinition(DigestAlgorithm.SHA256, "2019-01-01+00:00"),
                createSignatureAlgorithmDefinition(SignatureAlgorithm.RSA_SHA224, Arrays.asList(
                        new EvaluationType("2010-08-01", Arrays.asList(new ParameterType(786, MODULES_LENGTH))),
                        new EvaluationType("2019-10-01", Arrays.asList(new ParameterType(1024, MODULES_LENGTH))),
                        new EvaluationType("2019-10-01", Arrays.asList(new ParameterType(1536, MODULES_LENGTH))),
                        new EvaluationType("2029-01-01", Arrays.asList(new ParameterType(1900, MODULES_LENGTH))),
                        new EvaluationType("2029-01-01", Arrays.asList(new ParameterType(3000, MODULES_LENGTH)))
                )),
                createEncryptionAlgorithmDefinition(EncryptionAlgorithm.RSA, Arrays.asList(
                        new EvaluationType("2010-08-01", Arrays.asList(new ParameterType(786, MODULES_LENGTH))),
                        new EvaluationType("2019-10-01", Arrays.asList(new ParameterType(1024, MODULES_LENGTH))),
                        new EvaluationType("2019-10-01", Arrays.asList(new ParameterType(1536, MODULES_LENGTH))),
                        new EvaluationType("2025-01-01", Arrays.asList(new ParameterType(3000, MODULES_LENGTH))),
                        new EvaluationType(null, Arrays.asList(new ParameterType(4096, MODULES_LENGTH)))
                ))
        )));

        cryptographicSuite = new CryptographicSuiteJsonWrapper(new JsonObjectWrapper(new JsonObject(securitySuitabilityPolicyMap)));
        assertEquals(expected, new HashMap<>(cryptographicSuite.getAcceptableSignatureAlgorithmsWithExpirationDates()));
    }

    @Test
    void dss3655EcdsaTest() {
        Map<JsonString, JsonValue> securitySuitabilityPolicyMap = new HashMap<>();

        securitySuitabilityPolicyMap.put(new JsonString("Algorithm"), new JsonArray(Arrays.asList(
                createSignatureAlgorithmDefinition(SignatureAlgorithm.ECDSA_SHA224, Arrays.asList(
                        new EvaluationType("2012-08-01", Arrays.asList(
                                new ParameterType(160, PLENGTH),
                                new ParameterType(160, QLENGTH))),
                        new EvaluationType("2012-08-01", Arrays.asList(
                                new ParameterType(163, PLENGTH),
                                new ParameterType(163, QLENGTH))),
                        new EvaluationType("2029-01-01", Arrays.asList(
                                new ParameterType(224, PLENGTH),
                                new ParameterType(224, QLENGTH)))
                )),
                createEncryptionAlgorithmDefinition(EncryptionAlgorithm.ECDSA, Arrays.asList(
                        new EvaluationType("2012-08-01", Arrays.asList(
                                new ParameterType(160, PLENGTH),
                                new ParameterType(160, QLENGTH))),
                        new EvaluationType("2012-08-01", Arrays.asList(
                                new ParameterType(163, PLENGTH),
                                new ParameterType(163, QLENGTH))),
                        new EvaluationType("2021-10-01", Arrays.asList(
                                new ParameterType(256, PLENGTH),
                                new ParameterType(256, QLENGTH))),
                        new EvaluationType(null, Arrays.asList(
                                new ParameterType(384, PLENGTH),
                                new ParameterType(384, QLENGTH)))
                )))
        ));

        Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("GMT+0"));
        cal.clear();
        Map<SignatureAlgorithmWithMinKeySize, Date> expected = new HashMap<>();

        cal.set(2012, Calendar.AUGUST, 1);
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA224, 160), cal.getTime());
        cal.set(2012, Calendar.AUGUST, 1);
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA224, 163), cal.getTime());
        cal.set(2029, Calendar.JANUARY, 1);
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA224, 224), cal.getTime());

        CryptographicSuiteJsonWrapper cryptographicSuite = new CryptographicSuiteJsonWrapper(new JsonObjectWrapper(new JsonObject(securitySuitabilityPolicyMap)));
        assertEquals(expected, new HashMap<>(cryptographicSuite.getAcceptableSignatureAlgorithmsWithExpirationDates()));

        // Opposite order test

        securitySuitabilityPolicyMap = new HashMap<>();

        securitySuitabilityPolicyMap.put(new JsonString("Algorithm"), new JsonArray(Arrays.asList(
                createEncryptionAlgorithmDefinition(EncryptionAlgorithm.ECDSA, Arrays.asList(
                        new EvaluationType("2012-08-01", Arrays.asList(
                                new ParameterType(160, PLENGTH),
                                new ParameterType(160, QLENGTH))),
                        new EvaluationType("2012-08-01", Arrays.asList(
                                new ParameterType(163, PLENGTH),
                                new ParameterType(163, QLENGTH))),
                        new EvaluationType("2021-10-01", Arrays.asList(
                                new ParameterType(256, PLENGTH),
                                new ParameterType(256, QLENGTH))),
                        new EvaluationType(null, Arrays.asList(
                                new ParameterType(384, PLENGTH),
                                new ParameterType(384, QLENGTH)))
                )),
                createSignatureAlgorithmDefinition(SignatureAlgorithm.ECDSA_SHA224, Arrays.asList(
                        new EvaluationType("2012-08-01", Arrays.asList(
                                new ParameterType(160, PLENGTH),
                                new ParameterType(160, QLENGTH))),
                        new EvaluationType("2012-08-01", Arrays.asList(
                                new ParameterType(163, PLENGTH),
                                new ParameterType(163, QLENGTH))),
                        new EvaluationType("2029-01-01", Arrays.asList(
                                new ParameterType(224, PLENGTH),
                                new ParameterType(224, QLENGTH)))
                )))
        ));

        cryptographicSuite = new CryptographicSuiteJsonWrapper(new JsonObjectWrapper(new JsonObject(securitySuitabilityPolicyMap)));
        assertEquals(expected, cryptographicSuite.getAcceptableSignatureAlgorithmsWithExpirationDates());

        // add DigestAlgo

        securitySuitabilityPolicyMap = new HashMap<>();

        securitySuitabilityPolicyMap.put(new JsonString("Algorithm"), new JsonArray(Arrays.asList(
                createSignatureAlgorithmDefinition(SignatureAlgorithm.ECDSA_SHA224, Arrays.asList(
                        new EvaluationType("2012-08-01", Arrays.asList(
                                new ParameterType(160, PLENGTH),
                                new ParameterType(160, QLENGTH))),
                        new EvaluationType("2012-08-01", Arrays.asList(
                                new ParameterType(163, PLENGTH),
                                new ParameterType(163, QLENGTH))),
                        new EvaluationType("2029-01-01", Arrays.asList(
                                new ParameterType(224, PLENGTH),
                                new ParameterType(224, QLENGTH)))
                )),
                createEncryptionAlgorithmDefinition(EncryptionAlgorithm.ECDSA, Arrays.asList(
                        new EvaluationType("2012-08-01", Arrays.asList(
                                new ParameterType(160, PLENGTH),
                                new ParameterType(160, QLENGTH))),
                        new EvaluationType("2012-08-01", Arrays.asList(
                                new ParameterType(163, PLENGTH),
                                new ParameterType(163, QLENGTH))),
                        new EvaluationType("2021-10-01", Arrays.asList(
                                new ParameterType(256, PLENGTH),
                                new ParameterType(256, QLENGTH))),
                        new EvaluationType(null, Arrays.asList(
                                new ParameterType(384, PLENGTH),
                                new ParameterType(384, QLENGTH)))
                )),
                createDigestAlgorithmDefinition(DigestAlgorithm.SHA256, null)
        )));

        expected = new HashMap<>();

        cal.set(2012, Calendar.AUGUST, 1);
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA224, 160), cal.getTime());
        cal.set(2012, Calendar.AUGUST, 1);
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA224, 163), cal.getTime());
        cal.set(2029, Calendar.JANUARY, 1);
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA224, 224), cal.getTime());

        cal.set(2012, Calendar.AUGUST, 1);
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA256, 160), cal.getTime());
        cal.set(2012, Calendar.AUGUST, 1);
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA256, 163), cal.getTime());
        cal.set(2021, Calendar.OCTOBER, 1);
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA256, 256), cal.getTime());

        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA256, 384), null);

        cryptographicSuite = new CryptographicSuiteJsonWrapper(new JsonObjectWrapper(new JsonObject(securitySuitabilityPolicyMap)));
        assertEquals(expected, new HashMap<>(cryptographicSuite.getAcceptableSignatureAlgorithmsWithExpirationDates()));

        // opposite test

        securitySuitabilityPolicyMap = new HashMap<>();

        securitySuitabilityPolicyMap.put(new JsonString("Algorithm"), new JsonArray(Arrays.asList(
                createDigestAlgorithmDefinition(DigestAlgorithm.SHA256, null),
                createSignatureAlgorithmDefinition(SignatureAlgorithm.ECDSA_SHA224, Arrays.asList(
                        new EvaluationType("2012-08-01", Arrays.asList(
                                new ParameterType(160, PLENGTH),
                                new ParameterType(160, QLENGTH))),
                        new EvaluationType("2012-08-01", Arrays.asList(
                                new ParameterType(163, PLENGTH),
                                new ParameterType(163, QLENGTH))),
                        new EvaluationType("2029-01-01", Arrays.asList(
                                new ParameterType(224, PLENGTH),
                                new ParameterType(224, QLENGTH)))
                )),
                createEncryptionAlgorithmDefinition(EncryptionAlgorithm.ECDSA, Arrays.asList(
                        new EvaluationType("2012-08-01", Arrays.asList(
                                new ParameterType(160, PLENGTH),
                                new ParameterType(160, QLENGTH))),
                        new EvaluationType("2012-08-01", Arrays.asList(
                                new ParameterType(163, PLENGTH),
                                new ParameterType(163, QLENGTH))),
                        new EvaluationType("2021-10-01", Arrays.asList(
                                new ParameterType(256, PLENGTH),
                                new ParameterType(256, QLENGTH))),
                        new EvaluationType(null, Arrays.asList(
                                new ParameterType(384, PLENGTH),
                                new ParameterType(384, QLENGTH)))
                ))
        )));

        cryptographicSuite = new CryptographicSuiteJsonWrapper(new JsonObjectWrapper(new JsonObject(securitySuitabilityPolicyMap)));
        assertEquals(expected, new HashMap<>(cryptographicSuite.getAcceptableSignatureAlgorithmsWithExpirationDates()));

        // same DigestAlgo

        securitySuitabilityPolicyMap = new HashMap<>();

        securitySuitabilityPolicyMap.put(new JsonString("Algorithm"), new JsonArray(Arrays.asList(
                createSignatureAlgorithmDefinition(SignatureAlgorithm.ECDSA_SHA224, Arrays.asList(
                        new EvaluationType("2012-08-01", Arrays.asList(
                                new ParameterType(160, PLENGTH),
                                new ParameterType(160, QLENGTH))),
                        new EvaluationType("2012-08-01", Arrays.asList(
                                new ParameterType(163, PLENGTH),
                                new ParameterType(163, QLENGTH))),
                        new EvaluationType("2029-01-01", Arrays.asList(
                                new ParameterType(224, PLENGTH),
                                new ParameterType(224, QLENGTH)))
                )),
                createEncryptionAlgorithmDefinition(EncryptionAlgorithm.ECDSA, Arrays.asList(
                        new EvaluationType("2012-08-01", Arrays.asList(
                                new ParameterType(160, PLENGTH),
                                new ParameterType(160, QLENGTH))),
                        new EvaluationType("2012-08-01", Arrays.asList(
                                new ParameterType(163, PLENGTH),
                                new ParameterType(163, QLENGTH))),
                        new EvaluationType("2021-10-01", Arrays.asList(
                                new ParameterType(256, PLENGTH),
                                new ParameterType(256, QLENGTH))),
                        new EvaluationType(null, Arrays.asList(
                                new ParameterType(384, PLENGTH),
                                new ParameterType(384, QLENGTH)))
                )),
                createDigestAlgorithmDefinition(DigestAlgorithm.SHA224, null)
        )));

        expected = new HashMap<>();

        // SignatureAlgorithm takes precedence
        cal.set(2012, Calendar.AUGUST, 1);
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA224, 160), cal.getTime());
        cal.set(2012, Calendar.AUGUST, 1);
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA224, 163), cal.getTime());
        cal.set(2029, Calendar.JANUARY, 1);
        expected.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA224, 224), cal.getTime());

        cryptographicSuite = new CryptographicSuiteJsonWrapper(new JsonObjectWrapper(new JsonObject(securitySuitabilityPolicyMap)));
        assertEquals(expected, new HashMap<>(cryptographicSuite.getAcceptableSignatureAlgorithmsWithExpirationDates()));
    }

    @Test
    void getCryptographicSuiteUpdateDateTest() {
        Map<JsonString, JsonValue> securitySuitabilityPolicyMap = new HashMap<>();
        JsonObject jsonObject = new JsonObject(securitySuitabilityPolicyMap);

        CryptographicSuiteJsonWrapper cryptographicSuite = new CryptographicSuiteJsonWrapper(new JsonObjectWrapper(jsonObject));
        assertNull(cryptographicSuite.getCryptographicSuiteUpdateDate());

        securitySuitabilityPolicyMap.put(new JsonString("PolicyIssueDate"), new JsonString("2024-10-13T00:00:00.000+01:00"));

        cryptographicSuite = new CryptographicSuiteJsonWrapper(new JsonObjectWrapper(jsonObject));

        Calendar calendar = Calendar.getInstance();
        calendar.setTimeZone(TimeZone.getTimeZone("GMT+1"));
        calendar.clear();

        calendar.set(2024, Calendar.OCTOBER, 13);

        assertEquals(calendar.getTime(), cryptographicSuite.getCryptographicSuiteUpdateDate());
    }

    private JsonObject createDigestAlgorithmDefinition(DigestAlgorithm digestAlgorithm, String expirationTime) {
        Map<JsonString, JsonValue> algorithmMap = new HashMap<>();

        Map<JsonString, JsonValue> algorithmIdentifierMap = new HashMap<>();
        algorithmIdentifierMap.put(new JsonString("Name"), new JsonString(digestAlgorithm.getName()));
        if (digestAlgorithm.getOid() != null) {
            algorithmIdentifierMap.put(new JsonString("ObjectIdentifier"), new JsonString(digestAlgorithm.getOid()));
        }
        if (digestAlgorithm.getUri() != null) {
            algorithmIdentifierMap.put(new JsonString("URI"), new JsonString(digestAlgorithm.getUri()));
        }

        algorithmMap.put(new JsonString("AlgorithmIdentifier"), new JsonObject(algorithmIdentifierMap));

        List<JsonValue> evaluationList = new ArrayList<>();

        Map<JsonString, JsonValue> validityMap = new HashMap<>();
        if (expirationTime != null) {
            validityMap.put(new JsonString("End"), new JsonString(expirationTime));
        }
        Map<JsonString, JsonValue> evaluationObject = new HashMap<>();
        evaluationObject.put(new JsonString("Validity"), new JsonObject(validityMap));
        evaluationList.add(new JsonObject(evaluationObject));

        JsonArray evaluationArray = new JsonArray(evaluationList);
        algorithmMap.put(new JsonString("Evaluation"), evaluationArray);

        return new JsonObject(algorithmMap);
    }

    private JsonObject createEncryptionAlgorithmDefinition(EncryptionAlgorithm encryptionAlgorithm, List<EvaluationType> evaluationTypes) {
        Map<JsonString, JsonValue> algorithmMap = new HashMap<>();

        Map<JsonString, JsonValue> algorithmIdentifierMap = new HashMap<>();
        algorithmIdentifierMap.put(new JsonString("Name"), new JsonString(encryptionAlgorithm.getName()));
        if (encryptionAlgorithm.getOid() != null) {
            algorithmIdentifierMap.put(new JsonString("ObjectIdentifier"), new JsonString(encryptionAlgorithm.getOid()));
        }

        algorithmMap.put(new JsonString("AlgorithmIdentifier"), new JsonObject(algorithmIdentifierMap));

        algorithmMap.put(new JsonString("Evaluation"), createEvaluationArray(evaluationTypes));

        return new JsonObject(algorithmMap);
    }

    private JsonObject createSignatureAlgorithmDefinition(SignatureAlgorithm signatureAlgorithm, List<EvaluationType> evaluationTypes) {
        Map<JsonString, JsonValue> algorithmMap = new HashMap<>();

        Map<JsonString, JsonValue> algorithmIdentifierMap = new HashMap<>();
        algorithmIdentifierMap.put(new JsonString("Name"), new JsonString(signatureAlgorithm.getName()));
        if (signatureAlgorithm.getOid() != null) {
            algorithmIdentifierMap.put(new JsonString("ObjectIdentifier"), new JsonString(signatureAlgorithm.getOid()));
        }

        algorithmMap.put(new JsonString("AlgorithmIdentifier"), new JsonObject(algorithmIdentifierMap));

        algorithmMap.put(new JsonString("Evaluation"), createEvaluationArray(evaluationTypes));

        return new JsonObject(algorithmMap);
    }

    private JsonArray createEvaluationArray(List<EvaluationType> evaluationTypes) {
        List<JsonValue> evaluationList = new ArrayList<>();
        if (evaluationTypes != null && !evaluationTypes.isEmpty()) {
            for (EvaluationType evaluationType : evaluationTypes) {
                Map<JsonString, JsonValue> evaluationMap = new HashMap<>();
                Map<JsonString, JsonValue> validityMap = new HashMap<>();
                if (evaluationType.validityEnd != null) {
                    validityMap.put(new JsonString("End"), new JsonString(evaluationType.validityEnd));
                }
                evaluationMap.put(new JsonString("Validity"), new JsonObject(validityMap));
                if (evaluationType.parameterList != null && !evaluationType.parameterList.isEmpty()) {
                    List<JsonValue> paremeterList = new ArrayList<>();
                    for (ParameterType parameterType : evaluationType.parameterList) {
                        if (parameterType.minKeyLength != null) {
                            Map<JsonString, JsonValue> parameterMap = new HashMap<>();
                            parameterMap.put(new JsonString("Min"), new JsonNumber(parameterType.minKeyLength));
                            if (parameterType.parameterName != null) {
                                parameterMap.put(new JsonString("name"), new JsonString(parameterType.parameterName));
                            }
                            paremeterList.add(new JsonObject(parameterMap));
                        }
                    }
                    evaluationMap.put(new JsonString("Parameter"), new JsonArray(paremeterList));
                }
                evaluationList.add(new JsonObject(evaluationMap));
            }

        } else {
            // create empty validity
            Map<JsonString, JsonValue> evaluationMap = new HashMap<>();
            Map<JsonString, JsonValue> validityMap = new HashMap<>();
            evaluationMap.put(new JsonString("Validity"), new JsonObject(validityMap));
            evaluationList.add(new JsonObject(evaluationMap));
        }
        return new JsonArray(evaluationList);
    }

    @Test
    void levelsTest() {
        Map<JsonString, JsonValue> securitySuitabilityPolicyMap = new HashMap<>();
        JsonObject jsonObject = new JsonObject(securitySuitabilityPolicyMap);

        CryptographicSuiteJsonWrapper cryptographicSuite = new CryptographicSuiteJsonWrapper(new JsonObjectWrapper(jsonObject));
        assertNull(cryptographicSuite.getCryptographicSuiteUpdateDate());
        
        assertEquals(Level.FAIL, cryptographicSuite.getLevel()); // default
        // inherited from default
        assertEquals(Level.FAIL, cryptographicSuite.getAcceptableDigestAlgorithmsLevel());
        assertEquals(Level.FAIL, cryptographicSuite.getAcceptableSignatureAlgorithmsLevel());
        assertEquals(Level.FAIL, cryptographicSuite.getAcceptableSignatureAlgorithmsMiniKeySizeLevel());
        assertEquals(Level.FAIL, cryptographicSuite.getAlgorithmsExpirationDateLevel());
        assertEquals(Level.WARN, cryptographicSuite.getAlgorithmsExpirationDateAfterUpdateLevel()); // default

        cryptographicSuite.setLevel(Level.IGNORE);
        assertEquals(Level.IGNORE, cryptographicSuite.getLevel());
        assertEquals(Level.IGNORE, cryptographicSuite.getAcceptableDigestAlgorithmsLevel());
        assertEquals(Level.IGNORE, cryptographicSuite.getAcceptableSignatureAlgorithmsLevel());
        assertEquals(Level.IGNORE, cryptographicSuite.getAcceptableSignatureAlgorithmsMiniKeySizeLevel());
        assertEquals(Level.IGNORE, cryptographicSuite.getAlgorithmsExpirationDateLevel());
        assertEquals(Level.WARN, cryptographicSuite.getAlgorithmsExpirationDateAfterUpdateLevel());

        cryptographicSuite.setAlgorithmsExpirationTimeAfterPolicyUpdateLevel(Level.INFORM);
        assertEquals(Level.IGNORE, cryptographicSuite.getLevel());
        assertEquals(Level.IGNORE, cryptographicSuite.getAcceptableDigestAlgorithmsLevel());
        assertEquals(Level.IGNORE, cryptographicSuite.getAcceptableSignatureAlgorithmsLevel());
        assertEquals(Level.IGNORE, cryptographicSuite.getAcceptableSignatureAlgorithmsMiniKeySizeLevel());
        assertEquals(Level.IGNORE, cryptographicSuite.getAlgorithmsExpirationDateLevel());
        assertEquals(Level.INFORM, cryptographicSuite.getAlgorithmsExpirationDateAfterUpdateLevel());

        cryptographicSuite.setAcceptableDigestAlgorithmsLevel(Level.INFORM);
        assertEquals(Level.IGNORE, cryptographicSuite.getLevel());
        assertEquals(Level.INFORM, cryptographicSuite.getAcceptableDigestAlgorithmsLevel());
        assertEquals(Level.IGNORE, cryptographicSuite.getAcceptableSignatureAlgorithmsLevel());
        assertEquals(Level.IGNORE, cryptographicSuite.getAcceptableSignatureAlgorithmsMiniKeySizeLevel());
        assertEquals(Level.IGNORE, cryptographicSuite.getAlgorithmsExpirationDateLevel());
        assertEquals(Level.INFORM, cryptographicSuite.getAlgorithmsExpirationDateAfterUpdateLevel());

        cryptographicSuite.setAcceptableSignatureAlgorithmsLevel(Level.INFORM);
        assertEquals(Level.IGNORE, cryptographicSuite.getLevel());
        assertEquals(Level.INFORM, cryptographicSuite.getAcceptableDigestAlgorithmsLevel());
        assertEquals(Level.INFORM, cryptographicSuite.getAcceptableSignatureAlgorithmsLevel());
        assertEquals(Level.IGNORE, cryptographicSuite.getAcceptableSignatureAlgorithmsMiniKeySizeLevel());
        assertEquals(Level.IGNORE, cryptographicSuite.getAlgorithmsExpirationDateLevel());
        assertEquals(Level.INFORM, cryptographicSuite.getAlgorithmsExpirationDateAfterUpdateLevel());

        cryptographicSuite.setAcceptableSignatureAlgorithmsMiniKeySizeLevel(Level.INFORM);
        assertEquals(Level.IGNORE, cryptographicSuite.getLevel());
        assertEquals(Level.INFORM, cryptographicSuite.getAcceptableDigestAlgorithmsLevel());
        assertEquals(Level.INFORM, cryptographicSuite.getAcceptableSignatureAlgorithmsLevel());
        assertEquals(Level.INFORM, cryptographicSuite.getAcceptableSignatureAlgorithmsMiniKeySizeLevel());
        assertEquals(Level.IGNORE, cryptographicSuite.getAlgorithmsExpirationDateLevel());
        assertEquals(Level.INFORM, cryptographicSuite.getAlgorithmsExpirationDateAfterUpdateLevel());

        cryptographicSuite.setAlgorithmsExpirationDateLevel(Level.INFORM);
        assertEquals(Level.IGNORE, cryptographicSuite.getLevel());
        assertEquals(Level.INFORM, cryptographicSuite.getAcceptableDigestAlgorithmsLevel());
        assertEquals(Level.INFORM, cryptographicSuite.getAcceptableSignatureAlgorithmsLevel());
        assertEquals(Level.INFORM, cryptographicSuite.getAcceptableSignatureAlgorithmsMiniKeySizeLevel());
        assertEquals(Level.INFORM, cryptographicSuite.getAlgorithmsExpirationDateLevel());
        assertEquals(Level.INFORM, cryptographicSuite.getAlgorithmsExpirationDateAfterUpdateLevel());
    }

    private static class EvaluationType {

        private final String validityEnd;
        private final List<ParameterType> parameterList;

        public EvaluationType(final String validityEnd, final List<ParameterType> parameterList) {
            this.validityEnd = validityEnd;
            this.parameterList = parameterList;
        }

    }

    private static class ParameterType {
        private final Integer minKeyLength;
        private final String parameterName;

        public ParameterType(final Integer minKeyLength, final String parameterName) {
            this.minKeyLength = minKeyLength;
            this.parameterName = parameterName;
        }
    }

}
