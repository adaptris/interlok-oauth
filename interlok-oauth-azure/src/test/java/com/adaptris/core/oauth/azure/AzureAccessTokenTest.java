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

package com.adaptris.core.oauth.azure;

import static org.junit.jupiter.api.Assertions.fail;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.adaptris.core.CoreException;
import com.adaptris.core.util.LifecycleHelper;

@SuppressWarnings("deprecation")
public class AzureAccessTokenTest {

  @BeforeEach
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
