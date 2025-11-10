package eu.europa.esig.dss.validation.qwac;

import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class QWACUtilsTest {

    @Test
    void getTLSCertificateBindingUrlTest() {
        assertNull(QWACUtils.getTLSCertificateBindingUrl(null));
        assertNull(QWACUtils.getTLSCertificateBindingUrl(new HashMap<>()));

        Map<String, List<String>> map = new HashMap<>();
        map.put("content-type", Collections.singletonList("application/json"));
        assertNull(QWACUtils.getTLSCertificateBindingUrl(map));

        map.put("Link", Collections.singletonList("<https://example.org/>"));
        assertNull(QWACUtils.getTLSCertificateBindingUrl(map));

        map.put("Link", Collections.singletonList("<https://example.org/>; rel=\"index\""));
        assertNull(QWACUtils.getTLSCertificateBindingUrl(map));

        map.put("Link", Collections.singletonList("<https://example.org/>; rel=\"tls-certificate-binding\""));
        assertEquals("https://example.org/", QWACUtils.getTLSCertificateBindingUrl(map));

        map.put("Link", Collections.singletonList("<https://example.org/>; rel=\"tls-certificate-binding\", <https://example.com/>; rel=\"index\""));
        assertEquals("https://example.org/", QWACUtils.getTLSCertificateBindingUrl(map));
    }

}
