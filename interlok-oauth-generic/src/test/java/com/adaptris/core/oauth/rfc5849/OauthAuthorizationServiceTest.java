/*
 * Copyright 2019 Adaptris Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.adaptris.core.oauth.rfc5849;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import org.junit.jupiter.api.Test;
import com.adaptris.core.AdaptrisMessage;
import com.adaptris.core.CoreException;
import com.adaptris.core.DefaultMessageFactory;
import com.adaptris.core.ServiceException;
import com.adaptris.core.metadata.NoOpMetadataFilter;
import com.adaptris.core.util.LifecycleHelper;
import com.adaptris.interlok.junit.scaffolding.services.ExampleServiceCase;

public class OauthAuthorizationServiceTest extends ExampleServiceCase {

  @Test
  public void testService_Init() throws Exception {
    GenerateRfc5849Header service = new GenerateRfc5849Header();
    try {
      LifecycleHelper.initAndStart(service);
      fail();
    } catch (CoreException expected) {

    }
    service.setHttpMethod("POST");
    service.setUrl("http://localhost");
    LifecycleHelper.initAndStart(service);
  }


  @Test
  public void testService_Exception() throws Exception {
    GenerateRfc5849Header service =
        new GenerateRfc5849Header().withMethod("POST").withUrl("http://localhost");
    AdaptrisMessage msg = new DefaultMessageFactory().newMessage("Hello World");
    try {
      execute(service, msg);
      fail();
    } catch (ServiceException expected) {
    }
  }

  @Test
  public void testService() throws Exception {
    GenerateRfc5849Header service =
        new GenerateRfc5849Header().withMethod("POST").withUrl("http://localhost");
    AuthorizationDataTest.configure(service.getAuthorizationData());
    AdaptrisMessage msg = new DefaultMessageFactory().newMessage("Hello World");
    execute(service, msg);
    assertNotNull(msg.getMetadataValue("Authorization"));
    assertTrue(msg.getMetadataValue("Authorization").startsWith("OAuth"));
  }


  @Test
  public void testService_TargetMetadataKey() throws Exception {
    GenerateRfc5849Header service =
        new GenerateRfc5849Header().withMethod("POST").withUrl("http://localhost")
            .withTargetMetadataKey("X-Authorization")
            .withAuthorizationData(AuthorizationDataTest.configure(new AuthorizationData()));
    AdaptrisMessage msg = new DefaultMessageFactory().newMessage("Hello World");
    execute(service, msg);
    assertNull(msg.getMetadataValue("Authorization"));
    assertNotNull(msg.getMetadataValue("X-Authorization"));
    assertTrue(msg.getMetadataValue("X-Authorization").startsWith("OAuth"));
  }

  @Test
  public void testService_AdditionalData() throws Exception {
    GenerateRfc5849Header service =
        new GenerateRfc5849Header().withMethod("POST").withUrl("http://localhost")
            .withAdditionalData(new NoOpMetadataFilter());
    AuthorizationDataTest.configure(service.getAuthorizationData());
    AdaptrisMessage msg = new DefaultMessageFactory().newMessage("Hello World");
    msg.addMetadata("Hello", "World");
    execute(service, msg);
    assertNotNull(msg.getMetadataValue("Authorization"));
    assertTrue(msg.getMetadataValue("Authorization").startsWith("OAuth"));
  }


  @Override
  protected Object retrieveObjectForSampleConfig() {
    GenerateRfc5849Header service = new GenerateRfc5849Header();
    service.setHttpMethod("POST");
    service.setUrl("http://localhost");
    AuthorizationDataTest.configure(service.getAuthorizationData());
    return service;
  }
}
