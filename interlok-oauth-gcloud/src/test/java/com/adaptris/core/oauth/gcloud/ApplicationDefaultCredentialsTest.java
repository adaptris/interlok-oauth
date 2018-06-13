/*
    Copyright Adaptris Ltd.

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/

package com.adaptris.core.oauth.gcloud;

import com.adaptris.core.CoreException;
import com.adaptris.core.util.LifecycleHelper;
import org.junit.Test;
import org.mockito.Mockito;

import java.util.ArrayList;
import java.util.Collections;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;


public class ApplicationDefaultCredentialsTest {

  @Test
  public void testInitStart() throws Exception{
    ApplicationDefaultCredentials credentials = Mockito.spy(new ApplicationDefaultCredentials());
    credentials.setScopes(Collections.singletonList("scope"));
    LifecycleHelper.initAndStart(credentials);
    Mockito.verify(credentials,Mockito.times(1)).init();
    Mockito.verify(credentials,Mockito.times(1)).start();
    Mockito.verify(credentials,Mockito.times(1)).validateArguments();
  }

  @Test
  public void testStopClose() throws Exception{
    ApplicationDefaultCredentials credentials = Mockito.spy(new ApplicationDefaultCredentials());
    credentials.setScopes(Collections.singletonList("scope"));
    LifecycleHelper.stopAndClose(credentials);
    Mockito.verify(credentials,Mockito.times(1)).stop();
    Mockito.verify(credentials,Mockito.times(1)).close();
    Mockito.verify(credentials,Mockito.never()).validateArguments();
  }

  @Test
  public void testValidateArguments() throws Exception {
    ApplicationDefaultCredentials credentials = new ApplicationDefaultCredentials();
    validateArgumentsFail(credentials, "Scope is invalid");
    credentials.setScopes(new ArrayList<String>());
    validateArgumentsFail(credentials, "Scope is invalid");
    credentials.setScopes(Collections.singletonList("scope"));
    credentials.validateArguments();
  }

  private void validateArgumentsFail(ScopedCredentials credentials, String message){
    try {
      credentials.validateArguments();
      fail();
    } catch (CoreException expected){
      assertEquals(message, expected.getMessage());
    }
  }

  @Test
  public void testGetScopes() throws Exception {
    ApplicationDefaultCredentials credentials = new ApplicationDefaultCredentials();
    credentials.setScopes(Collections.singletonList("scope"));
    assertEquals(1, credentials.getScopes().size());
    assertEquals("scope", credentials.getScopes().get(0));
  }


  @Test
  public void testConstruct() throws Exception {
    ApplicationDefaultCredentials credentials = new ApplicationDefaultCredentials("scope");
    assertEquals(1, credentials.getScopes().size());
    assertEquals("scope", credentials.getScopes().get(0));
  }

}
