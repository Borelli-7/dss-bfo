package eu.europa.esig.dss.validation.qwac;

import eu.europa.esig.dss.detailedreport.DetailedReportFacade;
import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.enumerations.TSLType;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.identifier.Identifier;
import eu.europa.esig.dss.model.timedependent.TimeDependentValues;
import eu.europa.esig.dss.model.tsl.ParsingInfoRecord;
import eu.europa.esig.dss.model.tsl.TLInfo;
import eu.europa.esig.dss.model.tsl.TLValidationJobSummary;
import eu.europa.esig.dss.model.tsl.TrustProperties;
import eu.europa.esig.dss.model.tsl.TrustService;
import eu.europa.esig.dss.model.tsl.TrustServiceProvider;
import eu.europa.esig.dss.model.tsl.TrustServiceStatusAndInformationExtensions;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.simplecertificatereport.SimpleCertificateReportFacade;
import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlSimpleCertificateReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.ExternalResourcesOCSPSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.reports.CertificateReports;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.when;

public class QWACValidatorTest {

    @Test
    void testNoTrustAnchor() throws Exception {
        QWACValidator validator = QWACValidator.fromUrl("https://harica.gr");
        validator.setCertificateVerifier(new CommonCertificateVerifier());

        CertificateReports reports = validator.validate();
        validateReports(reports);
        reports.print();
    }

    @Test
    void testWithTrustAnchor() throws Exception {
        QWACValidator validator = QWACValidator.fromUrl("https://harica.gr");

        CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
        TrustedListsCertificateSource trustedListsCertificateSource = new TrustedListsCertificateSource();

        CertificateToken trustAnchor = DSSUtils.loadCertificateFromBase64EncodedString("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");

        TrustServiceProvider trustServiceProvider = new TrustServiceProvider();
        trustServiceProvider.setTerritory("EL");
        trustServiceProvider.setNames(new HashMap<String, List<String>>() {{ put("EN", Collections.singletonList(trustAnchor.getSubject().getRFC2253())); }} );
        trustServiceProvider.setRegistrationIdentifiers(Collections.singletonList("VATEL-099028220"));

        TrustServiceStatusAndInformationExtensions trustServiceStatusAndInformationExtensions =
                new TrustServiceStatusAndInformationExtensions.TrustServiceStatusAndInformationExtensionsBuilder()
                        .setNames(new HashMap<String, List<String>>() {{ put("EN", Collections.singletonList("EL Service")); }} )
                        .setType("http://uri.etsi.org/TrstSvc/Svctype/CA/QC")
                        .setStatus("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted")
                        .setStartDate(DSSUtils.parseRFCDate("2022-03-31T10:00:45Z"))
                        .setAdditionalServiceInfoUris(Collections.singletonList("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForWebSiteAuthentication"))
                        .build();
        TimeDependentValues<TrustServiceStatusAndInformationExtensions> timeDependentValues =
                new TimeDependentValues<>(Collections.singletonList(trustServiceStatusAndInformationExtensions));

        TrustService trustService = new TrustService(Collections.singletonList(trustAnchor), timeDependentValues);
        trustServiceProvider.setServices(Collections.singletonList(trustService));

        Identifier tlIdentifier = Mockito.mock(Identifier.class);
        when(tlIdentifier.asXmlId()).thenReturn("TL-ID");

        TLInfo tlInfo = Mockito.mock(TLInfo.class);
        when(tlInfo.getUrl()).thenReturn("https://www.eett.gr/tsl/EL-TSL.xml");
        when(tlInfo.getDSSId()).thenReturn(tlIdentifier);
        when(tlInfo.getDSSIdAsString()).thenReturn("TL-ID");

        ParsingInfoRecord parsingInfoRecord = Mockito.mock(ParsingInfoRecord.class);
        when(parsingInfoRecord.getTerritory()).thenReturn("EL");
        when(parsingInfoRecord.getTSLType()).thenReturn(TSLType.fromUri("http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric"));
        when(parsingInfoRecord.getSequenceNumber()).thenReturn(1);
        when(parsingInfoRecord.getVersion()).thenReturn(5);

        when(tlInfo.getParsingCacheInfo()).thenReturn(parsingInfoRecord);

        TrustProperties trustProperties = new TrustProperties(tlInfo, trustServiceProvider, timeDependentValues);

        Map<CertificateToken, List<TrustProperties>> mapOfTrustProperties = new HashMap<>();
        mapOfTrustProperties.put(trustAnchor, Collections.singletonList(trustProperties));

        trustedListsCertificateSource.setTrustPropertiesByCertificates(mapOfTrustProperties);

        TLValidationJobSummary tlValidationJobSummary = new TLValidationJobSummary(Collections.emptyList(), Collections.singletonList(tlInfo));
        trustedListsCertificateSource.setSummary(tlValidationJobSummary);

        certificateVerifier.addTrustedCertSources(trustedListsCertificateSource);

        ExternalResourcesOCSPSource ocspSource = new ExternalResourcesOCSPSource(new InMemoryDocument(Utils.fromBase64("MIIC0woBAKCCAswwggLIBgkrBgEFBQcwAQEEggK5MIICtTCBnqIWBBS17OabFnhprbHoSVZHWBP3j02mwxgPMjAyNTEwMzAxODI0NDVaMHMwcTBJMAkGBSsOAwIaBQAEFDkEBpvdWDPHlj7GB3poKeNUchLFBBS17OabFnhprbHoSVZHWBP3j02mwwIQJHmpheD6BFAVsL0YH5Qh8IAAGA8yMDI1MTAzMDE4MjQ0NVqgERgPMjAyNTExMDIxODI0NDRaMA0GCSqGSIb3DQEBCwUAA4ICAQCLH9Esmpy4fyS7Pm3v/acTJ34j88C5TgV2R2e5rDeS9pYNHAypDWQQC0dVN9IJ/RCY8oFddl9zxmDsqdObouP4VT7k5KEFoVUn5N2NOgKJ4mwQwQDDzPYwFmwrw75T8yaUt6vQPe2AKJhiIPDa2kbmw1mP12Ra9KyEGssiGJ2FvnzJOpfBR6hVud0YlziN3h73imn+/jLlxx4+r9YnaRTVIWUgwXvhQx+50Cucw8HnmKHG5K9p2QJTq0swkr8ueUE8jUwD51llh0XukPh/Z9RDEvMhR5Xk/CRB2HhwH4NAKroiDjZ1WZZCpvtsFGsboLm448F6BkLo9ALMVaU54CWhd41eBaR+zvCdI//EdRHplM0WcRfvokkdl+ZBDUcYxHSRuKMRzTtrCA80A/d+KlUM1bWoi+ZsTcxiwyY9PWT2ecdZsGQ7kMucFKi5itHnsmgGLwmZERrcBhGtAPE92fVrEaQeJZnteiX225jy7OSR3GNwZ1oV+hcACS0ZSZlP7kM8XquYZe3wF/8DU7DeakHsTNILnyeIUbcnxGcmyHnT9QdpGvsu1/gW13ExjyXUwTxI5/q18zpU4JEAVFRwscpdIVWZA49znpkxML3SswrTPGze/SelOk+Nlml2OSw1PPuxbfb0hIXu6RJlsFerSliFWfesRVDkzOLFk3ejjQlnOA==")));
        certificateVerifier.setOcspSource(ocspSource);

        validator.setCertificateVerifier(certificateVerifier);

        CertificateReports reports = validator.validate();
        reports.print();
        validateReports(reports);
    }

    private void validateReports(CertificateReports reports) throws Exception {
        assertNotNull(reports);
        assertNotNull(reports.getDiagnosticDataJaxb());
        assertNotNull(reports.getXmlDiagnosticData());
        assertNotNull(reports.getDetailedReportJaxb());
        assertNotNull(reports.getXmlDetailedReport());
        assertNotNull(reports.getSimpleReportJaxb());
        assertNotNull(reports.getXmlSimpleReport());

        DiagnosticDataFacade diagnosticDataFacade = DiagnosticDataFacade.newFacade();
        String marshalled = diagnosticDataFacade.marshall(reports.getDiagnosticDataJaxb(), true);
        assertNotNull(marshalled);
        XmlDiagnosticData unmarshalled = diagnosticDataFacade.unmarshall(marshalled);
        assertNotNull(unmarshalled);

        SimpleCertificateReportFacade simpleCertificateReportFacade = SimpleCertificateReportFacade.newFacade();
        String marshalledSimpleReport = simpleCertificateReportFacade.marshall(reports.getSimpleReportJaxb(), true);
        assertNotNull(marshalledSimpleReport);
        XmlSimpleCertificateReport unmarshalledSimpleReport = simpleCertificateReportFacade.unmarshall(marshalledSimpleReport);
        assertNotNull(unmarshalledSimpleReport);
        assertNotNull(simpleCertificateReportFacade.generateHtmlReport(marshalledSimpleReport));
        assertNotNull(simpleCertificateReportFacade.generateHtmlReport(reports.getSimpleReportJaxb()));

        DetailedReportFacade detailedReportFacade = DetailedReportFacade.newFacade();
        String marshalledDetailedReport = detailedReportFacade.marshall(reports.getDetailedReportJaxb(), true);
        assertNotNull(marshalledDetailedReport);
        XmlDetailedReport unmarshalledDetailedReport = detailedReportFacade.unmarshall(marshalledDetailedReport);
        assertNotNull(unmarshalledDetailedReport);
        assertNotNull(detailedReportFacade.generateHtmlReport(marshalledDetailedReport));
        assertNotNull(detailedReportFacade.generateHtmlReport(reports.getDetailedReportJaxb()));
    }

}
