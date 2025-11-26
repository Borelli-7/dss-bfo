package eu.europa.esig.dss.spi.client.http;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.http.ResponseEnvelope;
import eu.europa.esig.dss.spi.exception.DSSExternalResourceException;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Defines a map between URL and document to load the response data from offline source
 *
 */
public class AdvancedMemoryDataLoader implements AdvancedDataLoader {

    private static final long serialVersionUID = -2899281917849499181L;

    /** The map between URLs and the corresponding binary content */
    private Map<String, ResponseEnvelope> dataMap = new HashMap<>();

    /**
     * Default constructor
     *
     * @param dataMap a map between URLs and the corresponding response data content
     */
    public AdvancedMemoryDataLoader(Map<String, ResponseEnvelope> dataMap) {
        this.dataMap.putAll(dataMap);
    }

    @Override
    public byte[] get(String url) {
        return requestGet(url).getResponseBody();
    }

    @Override
    public DataAndUrl get(List<String> urlStrings) throws DSSException {
        for (String url : urlStrings) {
            byte[] data = get(url);
            if (data != null) {
                return new DataAndUrl(url, data);
            }
        }
        throw new DSSExternalResourceException(String.format("A content for URLs [%s] does not exist!", urlStrings));
    }

    @Override
    public byte[] post(String url, byte[] content) {
        return requestPost(url, content).getResponseBody();
    }

    @Override
    public void setContentType(String contentType) {
        throw new UnsupportedOperationException("Content type change is not supported by this implementation!");
    }

    @Override
    public ResponseEnvelope requestGet(String url) {
        return requestGet(url, true);
    }

    @Override
    public ResponseEnvelope requestGet(String url, boolean includeResponseDetails) {
        return requestGet(url, includeResponseDetails, true);
    }

    @Override
    public ResponseEnvelope requestGet(String url, boolean includeResponseDetails, boolean includeResponseBody) {
        ResponseEnvelope storedValue = dataMap.get(url);
        if (storedValue == null) {
            return new ResponseEnvelope();
        }

        ResponseEnvelope response = new ResponseEnvelope();
        if (includeResponseDetails) {
            response.setHeaders(storedValue.getHeaders());
            response.setTLSCertificates(storedValue.getTLSCertificates());
        }
        if (includeResponseBody) {
            response.setResponseBody(storedValue.getResponseBody());
        }
        return response;
    }

    @Override
    public ResponseEnvelope requestPost(String url, byte[] content) {
        return requestPost(url, content, true);
    }

    @Override
    public ResponseEnvelope requestPost(String url, byte[] content, boolean includeResponseDetails) {
        return requestPost(url, content, includeResponseDetails, true);
    }

    @Override
    public ResponseEnvelope requestPost(String url, byte[] content, boolean includeResponseDetails, boolean includeResponseBody) {
        return requestGet(url, includeResponseDetails, includeResponseBody);
    }

}