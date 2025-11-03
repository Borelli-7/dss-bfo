package eu.europa.esig.dss.spi.client.http;

import eu.europa.esig.dss.model.http.ResponseEnvelope;

/**
 * This data loader is used to perform a remote request (HTTP, HTTPS, etc.) and
 * retrieve a {@code eu.europa.esig.dss.model.http.ResponseEnvelope} object,
 * containing contextual information delivered from the response (response body, headers, session data, etc.).
 *
 */
public interface AdvancedDataLoader extends DataLoader {

    /**
     * Executes a GET request and returns an {@code HTTPResponse} object.
     * This method included the response message body, context and metadata within the response object.
     *
     * @param url {@link String} URL to perform request to
     * @return {@link ResponseEnvelope}
     */
    ResponseEnvelope requestGet(String url);

    /**
     * Executes a GET request and returns an {@code HTTPResponse} object.
     * Depending on the {@code includeResponseBody} parameter, the response message body will be either included
     * or omitted (consumed silently in void).
     *
     * @param url {@link String} URL to perform request to
     * @return {@link ResponseEnvelope}
     */
    ResponseEnvelope requestGet(String url, boolean includeResponseBody);

    /**
     * Executes a POST request and returns an {@code HTTPResponse} object.
     * This method included the response message body, context and metadata within the response object.
     *
     * @param url {@link String} URL to perform request to
     * @param content byte array containing request content for the POST call
     * @return {@link ResponseEnvelope}
     */
    ResponseEnvelope requestPost(String url, byte[] content);

    /**
     * Executes a POST request and returns an {@code HTTPResponse} object.
     * Depending on the {@code includeResponseBody} parameter, the response message body will be either included
     * or omitted (consumed silently in void).
     *
     * @param url {@link String} URL to perform request to
     * @param content byte array containing request content for the POST call
     * @return {@link ResponseEnvelope}
     */
    ResponseEnvelope requestPost(String url, byte[] content, boolean includeResponseBody);

}
