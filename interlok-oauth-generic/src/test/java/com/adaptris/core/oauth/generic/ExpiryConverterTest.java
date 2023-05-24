package com.adaptris.core.oauth.generic;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

public class ExpiryConverterTest {

  @Test
  public void testNone() {
    assertEquals(0, ExpiryConverter.NONE.asMillis("123456"));
    assertEquals("abcde", ExpiryConverter.NONE.convertExpiry("abcde"));
  }

  @Test
  public void testMilliseconds() {
    assertTrue(ExpiryConverter.MILLISECONDS.asMillis("123456") > 0);
    assertNotNull(ExpiryConverter.MILLISECONDS.convertExpiry("123456"));
  }

  @Test
  public void testSeconds() {
    assertTrue(ExpiryConverter.SECONDS.asMillis("600") > 0);
    assertNotNull(ExpiryConverter.SECONDS.convertExpiry("600"));
  }

  @Test
  public void testMinutes() {
    assertTrue(ExpiryConverter.MINUTES.asMillis("600") > 0);
    assertNotNull(ExpiryConverter.MINUTES.convertExpiry("600"));
  }

  @Test
  public void testHours() {
    assertTrue(ExpiryConverter.HOURS.asMillis("600") > 0);
    assertNotNull(ExpiryConverter.HOURS.convertExpiry("600"));
  }

  @Test
  public void testDays() {
    assertTrue(ExpiryConverter.DAYS.asMillis("600") > 0);
    assertNotNull(ExpiryConverter.DAYS.convertExpiry("600"));
  }
}
