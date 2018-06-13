package com.adaptris.core.oauth.azure;

import static org.junit.Assert.fail;

import org.junit.Before;
import org.junit.Test;

import com.adaptris.core.CoreException;
import com.adaptris.core.util.LifecycleHelper;

@SuppressWarnings("deprecation")
public class AzureAccessTokenTest {

  @Before
  public void setUp() throws Exception {

  }

  @Test
  public void testLifecycle() throws Exception {
    AzureAccessToken tokenBuilder = new AzureAccessToken();
    try {
      LifecycleHelper.init(tokenBuilder);
      fail();
    }
    catch (CoreException expected) {

    }
    tokenBuilder.withUsernamePassword("test", "test");
    tokenBuilder.withClientId("test");
    tokenBuilder.withResource("https://graph.microsoft.com");
    LifecycleHelper.stopAndClose(LifecycleHelper.initAndStart(tokenBuilder));
  }

}
