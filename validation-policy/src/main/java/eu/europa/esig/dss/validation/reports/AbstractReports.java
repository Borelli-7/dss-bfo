/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.validation.reports;

import java.io.IOException;

import javax.xml.bind.JAXBException;

import org.xml.sax.SAXException;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.DetailedReportFacade;
import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;

/**
 * This class is a container for all reports generated by the validation
 * process: diagnostic data, detailed report and simple report.
 */
public abstract class AbstractReports {

	protected boolean validateXml = false;

	private final DiagnosticData diagnosticDataWrapper;
	private final DetailedReport detailedReportWrapper;
	private String xmlDiagnosticData;
	private String xmlDetailedReport;

	/**
	 * This is the default constructor to instantiate this container.
	 *
	 * @param diagnosticDataJaxb
	 *                           the JAXB {@code XmlDiagnosticData}
	 * @param detailedReport
	 *                           the JAXB {@code XmlDetailedReport}
	 */
	protected AbstractReports(final XmlDiagnosticData diagnosticDataJaxb,
			final XmlDetailedReport detailedReport) {
		this.diagnosticDataWrapper = new DiagnosticData(diagnosticDataJaxb);
		this.detailedReportWrapper = new DetailedReport(detailedReport);
	}

	public void setValidateXml(boolean validateXml) {
		this.validateXml = validateXml;
	}

	/**
	 * This method returns the reference to the diagnostic data object generated
	 * during the validation process.
	 *
	 * @return the wrapper {@code DiagnosticData}
	 */
	public DiagnosticData getDiagnosticData() {
		return diagnosticDataWrapper;
	}

	/**
	 * This method returns the wrapper to manipulate the JAXB DetailedReport
	 * 
	 * @return the wrapper {@code DetailedReport}
	 */
	public DetailedReport getDetailedReport() {
		return detailedReportWrapper;
	}

	/**
	 * This method returns the JAXB DiagnosticData
	 * 
	 * @return the JAXB {@code XmlDiagnosticData}
	 */
	public XmlDiagnosticData getDiagnosticDataJaxb() {
		return diagnosticDataWrapper.getJaxbModel();
	}

	/**
	 * This method returns the JAXB DetailedReport
	 * 
	 * @return the JAXB {@code XmlDetailedReport}
	 */
	public XmlDetailedReport getDetailedReportJaxb() {
		return detailedReportWrapper.getJAXBModel();
	}

	public abstract String getXmlSimpleReport();

	/**
	 * This method returns the XML representation of the JAXB DiagnosticData String
	 * 
	 * @return a String with the XML content of the JAXB {@code XmlDiagnosticData}
	 * @throws DSSReportException - in case of marshalling error
	 */
	public String getXmlDiagnosticData() {
		try {
			if (xmlDiagnosticData == null) {
				xmlDiagnosticData = DiagnosticDataFacade.newFacade().marshall(getDiagnosticDataJaxb(), validateXml);
			}
			return xmlDiagnosticData;
		} catch (JAXBException | IOException | SAXException e) {
			throw new DSSReportException("An error occurred during marshalling of JAXB Diagnostic Data", e);
		}
	}

	/**
	 * This method returns the XML representation of the JAXB DetailedReport String
	 * 
	 * @return a String with the XML content of the JAXB {@code XmlDetailedReport}
	 * @throws DSSReportException - in case of marshalling error
	 */
	public String getXmlDetailedReport() throws DSSReportException {
		try {
			if (xmlDetailedReport == null) {
				xmlDetailedReport = DetailedReportFacade.newFacade().marshall(getDetailedReportJaxb(), validateXml);
			}
			return xmlDetailedReport;
		} catch (JAXBException | IOException | SAXException e) {
			throw new DSSReportException("An error occurred during marshalling of JAXB Detailed Report", e);
		}
	}

	/**
	 * For debug purpose.
	 */
	public void print() {
		System.out.println("----------------Diagnostic data-----------------");
		System.out.println(getXmlDiagnosticData());
		System.out.println("----------------Validation report---------------");
		System.out.println(getXmlDetailedReport());
		System.out.println("----------------Simple report-------------------");
		System.out.println(getXmlSimpleReport());
		System.out.println("------------------------------------------------");
	}

}