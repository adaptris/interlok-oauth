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
package com.adaptris.core.oauth.generic;

import static org.apache.commons.lang3.StringUtils.isBlank;
import java.io.StringReader;
import java.nio.charset.Charset;
import javax.validation.Valid;
import javax.xml.namespace.NamespaceContext;
import org.apache.commons.io.input.ReaderInputStream;
import org.w3c.dom.Document;
import com.adaptris.annotation.AdvancedConfig;
import com.adaptris.annotation.ComponentProfile;
import com.adaptris.annotation.DisplayOrder;
import com.adaptris.core.CoreException;
import com.adaptris.core.http.oauth.AccessToken;
import com.adaptris.core.util.DocumentBuilderFactoryBuilder;
import com.adaptris.core.util.ExceptionHelper;
import com.adaptris.core.util.XmlHelper;
import com.adaptris.util.KeyValuePairSet;
import com.adaptris.util.text.xml.SimpleNamespaceContext;
import com.adaptris.util.text.xml.XPath;
import com.thoughtworks.xstream.annotations.XStreamAlias;

/**
 * Handle an OAUTH XML response.
 *
 * <p>
 * Configure the various token values using standard {@code xpath} notation; they will be extracted
 * from the HTTP response to build the access token.
 * </p>
 *
 * @config oauth-xml-response
 */
@XStreamAlias("oauth-xml-response")
@ComponentProfile(since = "3.8.1", summary = "Handle an OAUTH XML response.", tag = "oauth,http,https")
@DisplayOrder(order = {"accessTokenPath", "tokenTypePath", "expiresPath", "refreshTokenPath", "expiryConverter"})
public class XmlResponseHandler extends ResponseHandlerImpl {
  /**
   * Default XPath to the TokenType - {@value #TOKEN_TYPE_PATH}
   *
   */
  public static final String TOKEN_TYPE_PATH = "//token_type";
  /**
   * Default XPath to the Access Token - {@value #ACCESS_TOKEN_PATH}
   *
   */
  public static final String ACCESS_TOKEN_PATH = "//access_token";
  /**
   * Default XPath to the Expires value - {@value #EXPIRES_PATH}
   *
   */
  public static final String EXPIRES_PATH = "//expires_in";

  /**
   * Default JSON path to the refresh token {@value #REFRESH_TOKEN_PATH}.
   */
  public static final String REFRESH_TOKEN_PATH = "//refresh_token";

  @Valid
  private KeyValuePairSet namespaceContext;
  @AdvancedConfig
  @Valid
  private DocumentBuilderFactoryBuilder xmlDocumentFactoryConfig;

  private transient NamespaceContext nsCtx;
  private transient DocumentBuilderFactoryBuilder factoryBuilder;

  public XmlResponseHandler() {
    super();
    setAccessTokenPath(ACCESS_TOKEN_PATH);
    setExpiresPath(EXPIRES_PATH);
    setTokenTypePath(TOKEN_TYPE_PATH);
    setRefreshTokenPath(REFRESH_TOKEN_PATH);
  }

  @Override
  public void init() throws CoreException {
    super.init();
    nsCtx = SimpleNamespaceContext.create(getNamespaceContext());
    factoryBuilder = DocumentBuilderFactoryBuilder.newInstanceIfNull(getXmlDocumentFactoryConfig(), nsCtx);
  }

  @Override
  public AccessToken buildToken(String loginResponse) throws CoreException {
    XPath xpath = XPath.newXPathInstance(factoryBuilder, nsCtx);
    try (ReaderInputStream in = ReaderInputStream.builder().setReader(new StringReader(loginResponse)).setCharset(Charset.defaultCharset()).get()) {
      Document xml = XmlHelper.createDocument(in, factoryBuilder);

      String accessToken = xpath.selectSingleTextItem(xml, getAccessTokenPath());
      if (isBlank(accessToken)) {
        throw new CoreException("Failed to extract access_token from " + getAccessTokenPath());
      }
      AccessToken token = new AccessToken(accessToken);
      applyIfNotBlank(xpath.selectSingleTextItem(xml, getTokenTypePath()), (s) -> {
        token.setType(s);
      });
      applyIfNotBlank(xpath.selectSingleTextItem(xml, getExpiresPath()), (s) -> {
        token.setExpiry(convertExpiry(s, getExpiryConverter()));
      });
      applyIfNotBlank(xpath.selectSingleTextItem(xml, getRefreshTokenPath()), (s) -> {
        token.setRefreshToken(s);
      });
      return token;
    } catch (Exception e) {
      throw ExceptionHelper.wrapCoreException(e);
    }
  }



  public KeyValuePairSet getNamespaceContext() {
    return namespaceContext;
  }

  public void setNamespaceContext(KeyValuePairSet kvps) {
    this.namespaceContext = kvps;
  }

  public XmlResponseHandler withNamespaceContext(KeyValuePairSet kvps) {
    setNamespaceContext(kvps);
    return this;
  }

  public DocumentBuilderFactoryBuilder getXmlDocumentFactoryConfig() {
    return xmlDocumentFactoryConfig;
  }

  public void setXmlDocumentFactoryConfig(DocumentBuilderFactoryBuilder xml) {
    this.xmlDocumentFactoryConfig = xml;
  }

  public XmlResponseHandler withXmlDocumentFactoryConfig(DocumentBuilderFactoryBuilder builder) {
    setXmlDocumentFactoryConfig(builder);
    return this;
  }
}
