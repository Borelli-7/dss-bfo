package eu.europa.esig.dss.validation.executor.certificate.qwac;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.validation.executor.certificate.DefaultCertificateProcessExecutor;
import eu.europa.esig.dss.validation.executor.certificate.DetailedReportForCertificateBuilder;

/**
 * Executes a QWAC certificate validation
 *
 */
public class QWACCertificateProcessExecutor extends DefaultCertificateProcessExecutor {

    /**
     * Default constructor
     */
    public QWACCertificateProcessExecutor() {
        // empty
    }

    @Override
    protected DetailedReportForCertificateBuilder getDetailedReportBuilder(DiagnosticData diagnosticData) {
        return new DetailedReportForQWACBuilder(getI18nProvider(), diagnosticData, policy, currentTime, certificateId);
    }

}
