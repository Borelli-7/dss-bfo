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
package eu.europa.esig.dss.validation.policy;

import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.policy.CryptographicSuite;
import eu.europa.esig.dss.model.policy.CryptographicSuiteFactory;
import eu.europa.esig.dss.model.policy.SignatureAlgorithmWithMinKeySize;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.model.policy.ValidationPolicyFactory;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.Set;
import java.util.TimeZone;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class DefaultCryptographicSuiteTest {

    private static Stream<Arguments> data() {
        List<Arguments> args = new ArrayList<>();

        ServiceLoader<ValidationPolicyFactory> valPolicyLoader = ServiceLoader.load(ValidationPolicyFactory.class);
        Iterator<ValidationPolicyFactory> valPolicyOptions = valPolicyLoader.iterator();
        while (valPolicyOptions.hasNext()) {
            ValidationPolicyFactory factory = valPolicyOptions.next();
            ValidationPolicy validationPolicy = factory.loadDefaultValidationPolicy();
            CryptographicSuite cryptographicSuite = validationPolicy.getSignatureCryptographicConstraint(Context.SIGNATURE);
            args.add(Arguments.of(cryptographicSuite));
        }

        assertEquals(1, args.size());

        ServiceLoader<CryptographicSuiteFactory> cryptoSuiteLoader = ServiceLoader.load(CryptographicSuiteFactory.class);
        Iterator<CryptographicSuiteFactory> cryptoSuiteOptions = cryptoSuiteLoader.iterator();
        while (cryptoSuiteOptions.hasNext()) {
            CryptographicSuiteFactory factory = cryptoSuiteOptions.next();
            CryptographicSuite cryptographicSuite = factory.loadDefaultCryptographicSuite();
            args.add(Arguments.of(cryptographicSuite));
        }

        assertEquals(3, args.size()); // ensure number (+ xml and json crypto suites)

        return args.stream();
    }

    @ParameterizedTest(name = "Policy {index} : {0}")
    @MethodSource("data")
    void getAcceptableDigestAlgorithmsTest(CryptographicSuite cryptographicSuite) {
        List<DigestAlgorithm> acceptableDigestAlgorithms = cryptographicSuite.getAcceptableDigestAlgorithms();

        Set<DigestAlgorithm> expectedSet = new HashSet<>(Arrays.asList(
                DigestAlgorithm.MD5, DigestAlgorithm.SHA1,
                DigestAlgorithm.SHA224, DigestAlgorithm.SHA256, DigestAlgorithm.SHA384, DigestAlgorithm.SHA512,
                DigestAlgorithm.SHA3_256, DigestAlgorithm.SHA3_384, DigestAlgorithm.SHA3_512,
                DigestAlgorithm.RIPEMD160, DigestAlgorithm.WHIRLPOOL));

        assertEquals(expectedSet, new HashSet<>(acceptableDigestAlgorithms));
    }

    @ParameterizedTest(name = "Policy {index} : {0}")
    @MethodSource("data")
    void getAcceptableDigestAlgorithmsWithExpirationDatesTest(CryptographicSuite cryptographicSuite) {
        Map<DigestAlgorithm, Date> digestAlgorithmsWithExpirationDates = cryptographicSuite.getAcceptableDigestAlgorithmsWithExpirationDates();

        Calendar calendar = Calendar.getInstance();
        calendar.setTimeZone(TimeZone.getTimeZone("UTC"));
        calendar.clear();

        Map<DigestAlgorithm, Date> expectedMap = new LinkedHashMap<>();

        calendar.set(2004, Calendar.AUGUST, 1);
        expectedMap.put(DigestAlgorithm.MD5, calendar.getTime());

        calendar.set(2012, Calendar.AUGUST, 1);
        expectedMap.put(DigestAlgorithm.SHA1, calendar.getTime());

        calendar.set(2029, Calendar.JANUARY, 1);
        expectedMap.put(DigestAlgorithm.SHA224, calendar.getTime());

        expectedMap.put(DigestAlgorithm.SHA256, null);
        expectedMap.put(DigestAlgorithm.SHA384, null);
        expectedMap.put(DigestAlgorithm.SHA512, null);
        expectedMap.put(DigestAlgorithm.SHA3_256, null);
        expectedMap.put(DigestAlgorithm.SHA3_384, null);
        expectedMap.put(DigestAlgorithm.SHA3_512, null);

        calendar.set(2014, Calendar.AUGUST, 1);
        expectedMap.put(DigestAlgorithm.RIPEMD160, calendar.getTime());

        calendar.set(2020, Calendar.DECEMBER, 1);
        expectedMap.put(DigestAlgorithm.WHIRLPOOL, calendar.getTime());

        assertEquals(expectedMap, new LinkedHashMap<>(digestAlgorithmsWithExpirationDates));
    }

    @ParameterizedTest(name = "Policy {index} : {0}")
    @MethodSource("data")
    void getAcceptableSignatureAlgorithmsTest(CryptographicSuite cryptographicSuite) {
        List<SignatureAlgorithm> signatureAlgorithms = cryptographicSuite.getAcceptableSignatureAlgorithms();

        Set<SignatureAlgorithm> expectedSet = new HashSet<>(Arrays.asList(
                SignatureAlgorithm.RSA_MD5, SignatureAlgorithm.RSA_SHA1, SignatureAlgorithm.RSA_SHA224, SignatureAlgorithm.RSA_SHA256, 
                SignatureAlgorithm.RSA_SHA384, SignatureAlgorithm.RSA_SHA512, SignatureAlgorithm.RSA_SHA3_256,
                SignatureAlgorithm.RSA_SHA3_384, SignatureAlgorithm.RSA_SHA3_512, SignatureAlgorithm.RSA_RIPEMD160,
                
                SignatureAlgorithm.RSA_SSA_PSS_SHA1_MGF1, SignatureAlgorithm.RSA_SSA_PSS_SHA224_MGF1, SignatureAlgorithm.RSA_SSA_PSS_SHA256_MGF1,
                SignatureAlgorithm.RSA_SSA_PSS_SHA384_MGF1, SignatureAlgorithm.RSA_SSA_PSS_SHA512_MGF1, SignatureAlgorithm.RSA_SSA_PSS_SHA3_256_MGF1,
                SignatureAlgorithm.RSA_SSA_PSS_SHA3_384_MGF1, SignatureAlgorithm.RSA_SSA_PSS_SHA3_512_MGF1,

                SignatureAlgorithm.DSA_SHA1, SignatureAlgorithm.DSA_SHA224, SignatureAlgorithm.DSA_SHA256,
                SignatureAlgorithm.DSA_SHA384, SignatureAlgorithm.DSA_SHA512, SignatureAlgorithm.DSA_SHA3_256,
                SignatureAlgorithm.DSA_SHA3_384, SignatureAlgorithm.DSA_SHA3_512,
                
                SignatureAlgorithm.ECDSA_SHA1, SignatureAlgorithm.ECDSA_SHA224, SignatureAlgorithm.ECDSA_SHA256,
                SignatureAlgorithm.ECDSA_SHA384, SignatureAlgorithm.ECDSA_SHA512, SignatureAlgorithm.ECDSA_SHA3_256,
                SignatureAlgorithm.ECDSA_SHA3_384, SignatureAlgorithm.ECDSA_SHA3_512, SignatureAlgorithm.ECDSA_RIPEMD160,

                SignatureAlgorithm.PLAIN_ECDSA_SHA1, SignatureAlgorithm.PLAIN_ECDSA_SHA224, SignatureAlgorithm.PLAIN_ECDSA_SHA256,
                SignatureAlgorithm.PLAIN_ECDSA_SHA384, SignatureAlgorithm.PLAIN_ECDSA_SHA512, SignatureAlgorithm.PLAIN_ECDSA_SHA3_256,
                SignatureAlgorithm.PLAIN_ECDSA_SHA3_384, SignatureAlgorithm.PLAIN_ECDSA_SHA3_512, SignatureAlgorithm.PLAIN_ECDSA_RIPEMD160
        ));

        assertEquals(expectedSet, new HashSet<>(signatureAlgorithms));
    }

    @ParameterizedTest(name = "Policy {index} : {0}")
    @MethodSource("data")
    void getAcceptableSignatureAlgorithmsWithMinKeySizesTest(CryptographicSuite cryptographicSuite) {
        List<SignatureAlgorithmWithMinKeySize> signatureAlgorithms = cryptographicSuite.getAcceptableSignatureAlgorithmsWithMinKeySizes();

        Set<SignatureAlgorithmWithMinKeySize> expectedSet = new HashSet<>(Arrays.asList(
                new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_MD5, 786),
                new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA1, 786),
                new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA224, 786),
                new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA256, 786),
                new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA384, 786),
                new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA512, 786),
                new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA3_256,786),
                new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA3_384, 786),
                new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA3_512, 786),
                new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_RIPEMD160, 786),

                new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SSA_PSS_SHA1_MGF1, 786),
                new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SSA_PSS_SHA224_MGF1, 786),
                new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SSA_PSS_SHA256_MGF1,786),
                new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SSA_PSS_SHA384_MGF1, 786),
                new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SSA_PSS_SHA512_MGF1, 786),
                new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SSA_PSS_SHA3_256_MGF1,786),
                new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SSA_PSS_SHA3_384_MGF1, 786),
                new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SSA_PSS_SHA3_512_MGF1, 786),
                
                new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.DSA_SHA1, 1024), 
                new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.DSA_SHA224, 1024), 
                new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.DSA_SHA256, 1024), 
                new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.DSA_SHA384, 1024), 
                new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.DSA_SHA512, 1024), 
                new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.DSA_SHA3_256, 1024), 
                new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.DSA_SHA3_384, 1024), 
                new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.DSA_SHA3_512, 1024),

                new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA1, 160),
                new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA224, 160),
                new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA256, 160),
                new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA384, 160),
                new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA512, 160),
                new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA3_256, 160),
                new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA3_384, 160),
                new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA3_512, 160),
                new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_RIPEMD160, 160),

                new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.PLAIN_ECDSA_SHA1, 160),
                new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.PLAIN_ECDSA_SHA224, 160),
                new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.PLAIN_ECDSA_SHA256, 160),
                new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.PLAIN_ECDSA_SHA384, 160),
                new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.PLAIN_ECDSA_SHA512, 160),
                new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.PLAIN_ECDSA_SHA3_256, 160),
                new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.PLAIN_ECDSA_SHA3_384, 160),
                new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.PLAIN_ECDSA_SHA3_512, 160),
                new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.PLAIN_ECDSA_RIPEMD160, 160)
        ));

        assertEquals(expectedSet, new HashSet<>(signatureAlgorithms));
    }

    @ParameterizedTest(name = "Policy {index} : {0}")
    @MethodSource("data")
    void getAcceptableSignatureAlgorithmsWithExpirationDatesTest(CryptographicSuite cryptographicSuite) {
        Map<SignatureAlgorithmWithMinKeySize, Date> signatureAlgorithmsWithExpirationDates = cryptographicSuite.getAcceptableSignatureAlgorithmsWithExpirationDates();

        Calendar calendar = Calendar.getInstance();
        calendar.setTimeZone(TimeZone.getTimeZone("UTC"));
        calendar.clear();

        Map<SignatureAlgorithmWithMinKeySize, Date> expectedMap = new HashMap<>();

        calendar.set(2004, Calendar.AUGUST, 1);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_MD5, 786), calendar.getTime());
        calendar.set(2010, Calendar.AUGUST, 1);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA1, 786), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA224, 786), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA256, 786), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA384, 786), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA512, 786), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA3_256, 786), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA3_384, 786), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA3_512, 786), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_RIPEMD160, 786), calendar.getTime());

        calendar.set(2004, Calendar.AUGUST, 1);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_MD5, 1024), calendar.getTime());
        calendar.set(2012, Calendar.AUGUST, 1);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA1, 1024), calendar.getTime());
        calendar.set(2019, Calendar.OCTOBER, 1);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA224, 1024), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA256, 1024), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA384, 1024), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA512, 1024), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA3_256, 1024), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA3_384, 1024), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA3_512, 1024), calendar.getTime());
        calendar.set(2014, Calendar.AUGUST, 1);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_RIPEMD160, 1024), calendar.getTime());

        calendar.set(2004, Calendar.AUGUST, 1);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_MD5, 1536), calendar.getTime());
        calendar.set(2012, Calendar.AUGUST, 1);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA1, 1536), calendar.getTime());
        calendar.set(2019, Calendar.OCTOBER, 1);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA224, 1536), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA256, 1536), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA384, 1536), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA512, 1536), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA3_256, 1536), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA3_384, 1536), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA3_512, 1536), calendar.getTime());
        calendar.set(2014, Calendar.AUGUST, 1);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_RIPEMD160, 1536), calendar.getTime());

        calendar.set(2004, Calendar.AUGUST, 1);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_MD5, 1900), calendar.getTime());
        calendar.set(2012, Calendar.AUGUST, 1);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA1, 1900), calendar.getTime());
        calendar.set(2029, Calendar.JANUARY, 1);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA224, 1900), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA256, 1900), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA384, 1900), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA512, 1900), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA3_256, 1900), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA3_384, 1900), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA3_512, 1900), calendar.getTime());
        calendar.set(2014, Calendar.AUGUST, 1);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_RIPEMD160, 1900), calendar.getTime());

        calendar.set(2004, Calendar.AUGUST, 1);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_MD5, 3000), calendar.getTime());
        calendar.set(2012, Calendar.AUGUST, 1);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA1, 3000), calendar.getTime());
        calendar.set(2029, Calendar.JANUARY, 1);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA224, 3000), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA256, 3000), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA384, 3000), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA512, 3000), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA3_256, 3000), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA3_384, 3000), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SHA3_512, 3000), calendar.getTime());
        calendar.set(2014, Calendar.AUGUST, 1);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_RIPEMD160, 3000), calendar.getTime());

        calendar.set(2010, Calendar.AUGUST, 1);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SSA_PSS_SHA1_MGF1, 786), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SSA_PSS_SHA224_MGF1, 786), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SSA_PSS_SHA256_MGF1, 786), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SSA_PSS_SHA384_MGF1, 786), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SSA_PSS_SHA512_MGF1, 786), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SSA_PSS_SHA3_256_MGF1, 786), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SSA_PSS_SHA3_384_MGF1, 786), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SSA_PSS_SHA3_512_MGF1, 786), calendar.getTime());

        calendar.set(2012, Calendar.AUGUST, 1);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SSA_PSS_SHA1_MGF1, 1024), calendar.getTime());
        calendar.set(2019, Calendar.OCTOBER, 1);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SSA_PSS_SHA224_MGF1, 1024), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SSA_PSS_SHA256_MGF1, 1024), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SSA_PSS_SHA384_MGF1, 1024), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SSA_PSS_SHA512_MGF1, 1024), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SSA_PSS_SHA3_256_MGF1, 1024), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SSA_PSS_SHA3_384_MGF1, 1024), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SSA_PSS_SHA3_512_MGF1, 1024), calendar.getTime());

        calendar.set(2012, Calendar.AUGUST, 1);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SSA_PSS_SHA1_MGF1, 1536), calendar.getTime());
        calendar.set(2019, Calendar.OCTOBER, 1);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SSA_PSS_SHA224_MGF1, 1536), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SSA_PSS_SHA256_MGF1, 1536), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SSA_PSS_SHA384_MGF1, 1536), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SSA_PSS_SHA512_MGF1, 1536), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SSA_PSS_SHA3_256_MGF1, 1536), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SSA_PSS_SHA3_384_MGF1, 1536), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SSA_PSS_SHA3_512_MGF1, 1536), calendar.getTime());

        calendar.set(2012, Calendar.AUGUST, 1);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SSA_PSS_SHA1_MGF1, 1900), calendar.getTime());
        calendar.set(2029, Calendar.JANUARY, 1);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SSA_PSS_SHA224_MGF1, 1900), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SSA_PSS_SHA256_MGF1, 1900), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SSA_PSS_SHA384_MGF1, 1900), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SSA_PSS_SHA512_MGF1, 1900), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SSA_PSS_SHA3_256_MGF1, 1900), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SSA_PSS_SHA3_384_MGF1, 1900), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SSA_PSS_SHA3_512_MGF1, 1900), calendar.getTime());

        calendar.set(2012, Calendar.AUGUST, 1);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SSA_PSS_SHA1_MGF1, 3000), calendar.getTime());
        calendar.set(2029, Calendar.JANUARY, 1);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SSA_PSS_SHA224_MGF1, 3000), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SSA_PSS_SHA256_MGF1, 3000), null);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SSA_PSS_SHA384_MGF1, 3000), null);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SSA_PSS_SHA512_MGF1, 3000), null);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SSA_PSS_SHA3_256_MGF1, 3000), null);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SSA_PSS_SHA3_384_MGF1, 3000), null);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.RSA_SSA_PSS_SHA3_512_MGF1, 3000), null);

        calendar.set(2012, Calendar.AUGUST, 1);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.DSA_SHA1, 1024), calendar.getTime());
        calendar.set(2015, Calendar.DECEMBER, 1);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.DSA_SHA224, 1024), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.DSA_SHA256, 1024), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.DSA_SHA384, 1024), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.DSA_SHA512, 1024), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.DSA_SHA3_256, 1024), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.DSA_SHA3_384, 1024), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.DSA_SHA3_512, 1024), calendar.getTime());

        calendar.set(2012, Calendar.AUGUST, 1);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.DSA_SHA1, 1900), calendar.getTime());
        calendar.set(2029, Calendar.JANUARY, 1);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.DSA_SHA224, 1900), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.DSA_SHA256, 1900), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.DSA_SHA384, 1900), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.DSA_SHA512, 1900), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.DSA_SHA3_256, 1900), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.DSA_SHA3_384, 1900), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.DSA_SHA3_512, 1900), calendar.getTime());

        calendar.set(2012, Calendar.AUGUST, 1);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.DSA_SHA1, 3000), calendar.getTime());
        calendar.set(2029, Calendar.JANUARY, 1);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.DSA_SHA224, 3000), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.DSA_SHA256, 3000), null);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.DSA_SHA384, 3000), null);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.DSA_SHA512, 3000), null);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.DSA_SHA3_256, 3000), null);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.DSA_SHA3_384, 3000), null);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.DSA_SHA3_512, 3000), null);

        calendar.set(2012, Calendar.AUGUST, 1);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA1, 160), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA224, 160), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA256, 160), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA384, 160), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA512, 160), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA3_256, 160), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA3_384, 160), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA3_512, 160), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_RIPEMD160, 160), calendar.getTime());

        calendar.set(2012, Calendar.AUGUST, 1);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA1, 163), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA224, 163), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA256, 163), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA384, 163), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA512, 163), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA3_256, 163), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA3_384, 163), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA3_512, 163), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_RIPEMD160, 163), calendar.getTime());

        calendar.set(2012, Calendar.AUGUST, 1);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA1, 224), calendar.getTime());
        calendar.set(2021, Calendar.OCTOBER, 1);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA224, 224), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA256, 224), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA384, 224), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA512, 224), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA3_256, 224), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA3_384, 224), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA3_512, 224), calendar.getTime());
        calendar.set(2014, Calendar.AUGUST, 1);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_RIPEMD160, 224), calendar.getTime());

        calendar.set(2012, Calendar.AUGUST, 1);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA1, 256), calendar.getTime());
        calendar.set(2029, Calendar.JANUARY, 1);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA224, 256), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA256, 256), null);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA384, 256), null);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA512, 256), null);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA3_256, 256), null);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA3_384, 256), null);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_SHA3_512, 256), null);
        calendar.set(2014, Calendar.AUGUST, 1);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.ECDSA_RIPEMD160, 256), calendar.getTime());

        calendar.set(2012, Calendar.AUGUST, 1);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.PLAIN_ECDSA_SHA1, 160), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.PLAIN_ECDSA_SHA224, 160), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.PLAIN_ECDSA_SHA256, 160), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.PLAIN_ECDSA_SHA384, 160), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.PLAIN_ECDSA_SHA512, 160), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.PLAIN_ECDSA_SHA3_256, 160), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.PLAIN_ECDSA_SHA3_384, 160), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.PLAIN_ECDSA_SHA3_512, 160), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.PLAIN_ECDSA_RIPEMD160, 160), calendar.getTime());

        calendar.set(2012, Calendar.AUGUST, 1);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.PLAIN_ECDSA_SHA1, 163), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.PLAIN_ECDSA_SHA224, 163), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.PLAIN_ECDSA_SHA256, 163), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.PLAIN_ECDSA_SHA384, 163), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.PLAIN_ECDSA_SHA512, 163), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.PLAIN_ECDSA_SHA3_256, 163), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.PLAIN_ECDSA_SHA3_384, 163), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.PLAIN_ECDSA_SHA3_512, 163), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.PLAIN_ECDSA_RIPEMD160, 163), calendar.getTime());

        calendar.set(2012, Calendar.AUGUST, 1);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.PLAIN_ECDSA_SHA1, 224), calendar.getTime());
        calendar.set(2021, Calendar.OCTOBER, 1);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.PLAIN_ECDSA_SHA224, 224), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.PLAIN_ECDSA_SHA256, 224), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.PLAIN_ECDSA_SHA384, 224), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.PLAIN_ECDSA_SHA512, 224), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.PLAIN_ECDSA_SHA3_256, 224), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.PLAIN_ECDSA_SHA3_384, 224), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.PLAIN_ECDSA_SHA3_512, 224), calendar.getTime());
        calendar.set(2014, Calendar.AUGUST, 1);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.PLAIN_ECDSA_RIPEMD160, 224), calendar.getTime());

        calendar.set(2012, Calendar.AUGUST, 1);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.PLAIN_ECDSA_SHA1, 256), calendar.getTime());
        calendar.set(2029, Calendar.JANUARY, 1);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.PLAIN_ECDSA_SHA224, 256), calendar.getTime());
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.PLAIN_ECDSA_SHA256, 256), null);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.PLAIN_ECDSA_SHA384, 256), null);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.PLAIN_ECDSA_SHA512, 256), null);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.PLAIN_ECDSA_SHA3_256, 256), null);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.PLAIN_ECDSA_SHA3_384, 256), null);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.PLAIN_ECDSA_SHA3_512, 256), null);
        calendar.set(2014, Calendar.AUGUST, 1);
        expectedMap.put(new SignatureAlgorithmWithMinKeySize(SignatureAlgorithm.PLAIN_ECDSA_RIPEMD160, 256), calendar.getTime());

        assertEquals(expectedMap, new HashMap<>(signatureAlgorithmsWithExpirationDates));
    }

    @ParameterizedTest(name = "Policy {index} : {0}")
    @MethodSource("data")
    void getCryptographicSuiteUpdateDateTest(CryptographicSuite cryptographicSuite) {
        Calendar calendar = Calendar.getInstance();
        calendar.setTimeZone(TimeZone.getTimeZone("UTC"));
        calendar.clear();

        calendar.set(2024, Calendar.OCTOBER, 13);

        assertEquals(calendar.getTime(), cryptographicSuite.getCryptographicSuiteUpdateDate());
    }

}
