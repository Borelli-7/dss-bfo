package eu.europa.esig.dss.validation.executor.process;

import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

public class DSS3648ExecutorTest extends AbstractProcessExecutorTest {

    @Test
    void ltLevelTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/valid-diag-data-crl-lt.xml"));
        assertNotNull(diagnosticData);

        XmlTimestamp xmlTimestamp = diagnosticData.getUsedTimestamps().get(0);
        XmlCertificate timestampIssuer = xmlTimestamp.getSigningCertificate().getCertificate();

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        assertNull(simpleReport.getExtensionPeriodMin(simpleReport.getFirstSignatureId()));
        assertEquals(timestampIssuer.getNotAfter(), simpleReport.getExtensionPeriodMax(simpleReport.getFirstSignatureId()));

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void ltaLevelTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/valid-diag-data-crl-lta.xml"));
        assertNotNull(diagnosticData);

        XmlRevocation crlWrapper = diagnosticData.getUsedRevocations().get(1);

        XmlTimestamp xmlTimestamp = diagnosticData.getUsedTimestamps().get(0);
        XmlCertificate timestampIssuer = xmlTimestamp.getSigningCertificate().getCertificate();

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        assertEquals(crlWrapper.getNextUpdate(), simpleReport.getExtensionPeriodMin(simpleReport.getFirstSignatureId()));
        assertEquals(timestampIssuer.getNotAfter(), simpleReport.getExtensionPeriodMax(simpleReport.getFirstSignatureId()));

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

}
