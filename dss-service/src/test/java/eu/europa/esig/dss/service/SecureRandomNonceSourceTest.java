package eu.europa.esig.dss.service;

import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SecureRandomNonceSourceTest {

    @Test
    void test() {
        assertEquals(32, new SecureRandomNonceSource().getNonceValue().length);
        assertFalse(Arrays.equals(new SecureRandomNonceSource().getNonceValue(), new SecureRandomNonceSource().getNonceValue()));

        SecureRandomNonceSource secureRandomNonceSource = new SecureRandomNonceSource();
        assertFalse(Arrays.equals(secureRandomNonceSource.getNonceValue(), secureRandomNonceSource.getNonceValue()));

        assertEquals(1, new SecureRandomNonceSource(1).getNonceValue().length);
        assertEquals(16, new SecureRandomNonceSource(16).getNonceValue().length);
        assertEquals(30, new SecureRandomNonceSource(30).getNonceValue().length);
        assertEquals(32, new SecureRandomNonceSource(32).getNonceValue().length);
        assertEquals(64, new SecureRandomNonceSource(64).getNonceValue().length);
        assertEquals(128, new SecureRandomNonceSource(128).getNonceValue().length);
    }

    @Test
    void illegalValueTest() {
        Exception exception = assertThrows(IllegalArgumentException.class, () -> new SecureRandomNonceSource(-1));
        assertEquals("The nonce size cannot be 0 or smaller!", exception.getMessage());

        exception = assertThrows(IllegalArgumentException.class, () -> new SecureRandomNonceSource(0));
        assertEquals("The nonce size cannot be 0 or smaller!", exception.getMessage());
    }

}
