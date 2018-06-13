package com.adaptris.core.oauth.gcloud;

import com.adaptris.core.CoreException;
import com.adaptris.core.util.LifecycleHelper;
import org.junit.Test;
import org.mockito.Mockito;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;


public class KeyFileCredentialsTest {

  @Test
  public void testInitStart() throws Exception{
    KeyFileCredentials credentials = Mockito.spy(new KeyFileCredentials());
    File file = new File(KeyFileCredentialsTest.class.getClassLoader().getResource("interlok.json").getFile());
    credentials.setJsonKeyFile("file:///" + file.getAbsolutePath());
    credentials.setScopes(Collections.singletonList("scope"));
    LifecycleHelper.initAndStart(credentials);
    Mockito.verify(credentials,Mockito.times(1)).init();
    Mockito.verify(credentials,Mockito.times(1)).start();
    Mockito.verify(credentials,Mockito.times(1)).validateArguments();
  }

  @Test
  public void testStopClose() throws Exception{
    KeyFileCredentials credentials = Mockito.spy(new KeyFileCredentials());
    File file = new File(KeyFileCredentialsTest.class.getClassLoader().getResource("interlok.json").getFile());
    credentials.setJsonKeyFile("file:///" + file.getAbsolutePath());
    credentials.setScopes(Collections.singletonList("scope"));
    LifecycleHelper.stopAndClose(credentials);
    Mockito.verify(credentials,Mockito.times(1)).stop();
    Mockito.verify(credentials,Mockito.times(1)).close();
    Mockito.verify(credentials,Mockito.never()).validateArguments();
  }

  @Test
  public void testValidateArguments() throws Exception {
    KeyFileCredentials credentials = new KeyFileCredentials();
    validateArgumentsFail(credentials, "Json Key File is invalid");
    credentials.setJsonKeyFile("");
    validateArgumentsFail(credentials, "Json Key File is invalid");
    credentials.setJsonKeyFile("file:////opt/interlok/config/interlok.json");
    validateArgumentsFail(credentials, "Scope is invalid");
    credentials.setScopes(new ArrayList<String>());
    validateArgumentsFail(credentials, "Scope is invalid");
    credentials.setScopes(Collections.singletonList("scope"));
    credentials.validateArguments();
  }

  private void validateArgumentsFail(KeyFileCredentials credentials, String message){
    try {
      credentials.validateArguments();
      fail();
    } catch (CoreException expected){
      assertEquals(message, expected.getMessage());
    }
  }

  @Test
  public void testGetJsonKeyFile() throws Exception {
    KeyFileCredentials credentials = new KeyFileCredentials();
    credentials.setJsonKeyFile("/opt/interlok/file.json");
    assertEquals("/opt/interlok/file.json", credentials.getJsonKeyFile());
  }

  @Test
  public void testGetScopes() throws Exception {
    KeyFileCredentials credentials = new KeyFileCredentials();
    credentials.setScopes(Arrays.asList("scope"));
    assertEquals(1, credentials.getScopes().size());
    assertEquals("scope", credentials.getScopes().get(0));
  }

  @Test
  public void testConstruct() throws Exception {
    KeyFileCredentials credentials = new KeyFileCredentials("scope");
    assertEquals(1, credentials.getScopes().size());
    assertEquals("scope", credentials.getScopes().get(0));
  }

}