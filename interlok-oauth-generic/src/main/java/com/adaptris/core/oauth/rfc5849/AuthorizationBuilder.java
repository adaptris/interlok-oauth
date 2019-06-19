/*
 * Copyright 2019 Adaptris Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */
package com.adaptris.core.oauth.rfc5849;

import static java.lang.String.CASE_INSENSITIVE_ORDER;
import static java.util.stream.Collectors.joining;
import static org.apache.commons.lang3.StringUtils.isEmpty;
import static org.apache.commons.lang3.StringUtils.wrap;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.adaptris.core.AdaptrisMessage;
import com.adaptris.core.oauth.rfc5849.AuthorizationData.SignatureMethod;
import com.adaptris.core.util.Args;

/**
 * Build the Authorization header.
 * <p>
 * This is responsible for building the actual string that forms the {@code Authorization} header. It is not designed to be directly
 * configurable; you would configure {@link AuthorizationData} instead and use {@link AuthorizationData#builder(AdaptrisMessage)} to
 * get access to an instance of this class.
 * </p>
 */
public class AuthorizationBuilder {

  private static final String EQUALS = "=";
  private static final String REALM = "realm";
  private static final String OAUTH_VERIFIER = "oauth_verifier";
  private static final String OAUTH_TOKEN = "oauth_token";
  private static final String OAUTH_NONCE = "oauth_nonce";
  private static final String OAUTH_VERSION = "oauth_version";
  private static final String OAUTH_TIMESTAMP = "oauth_timestamp";
  private static final String OAUTH_SIGNATURE_METHOD = "oauth_signature_method";
  private static final String OAUTH_CONSUMER_KEY = "oauth_consumer_key";
  private static final String OAUTH_SIGNATURE = "oauth_signature";
  private static final String AMPERSAND = "&";
  private static final String COMMA = ",";

  private transient URL url;
  private transient String method;
  private transient String consumerKey;
  private transient String consumerSecret;

  private transient String accessToken;
  private transient String tokenSecret;
  private transient String nonce;

  private transient String realm;
  private transient String version;
  private transient String verifier;
  private transient boolean includeEmptyParams;
  private transient SignatureMethod signatureMethod;
  private transient Map<String, String> additionalData;

  private transient Logger log = LoggerFactory.getLogger(this.getClass());

  public AuthorizationBuilder() {
    setRealm("");
    setVersion("1.0");
    setVerifier("");
    setAccessToken("");
    setTokenSecret("");
    setSignatureMethod(SignatureMethod.HMAC_SHA1);
    setAdditionalData(new HashMap<>());
  }

  /**
   * Create the string that can be used as the {@code Authorization} header.
   * 
   */
  public String build() throws Exception {
    Args.notBlank(getConsumerKey(), "consumerKey");
    Args.notBlank(getConsumerSecret(), "consumerSecret");
    Args.notBlank(getNonce(), "nonce");
    Args.notBlank(getMethod(), "method");
    Args.notNull(getSignatureMethod(), "signatureMethod");
    Args.notNull(getUrl(), "url");
    String timestamp = String.valueOf(Instant.now().getEpochSecond());
    String stringToSign = buildStringToSign(getMethod(), getUrl(), filter(oauthParams(timestamp)),
        getAdditionalData());
    log.trace("Signing string [{}]", stringToSign);
    System.err.println("Signing string [" + stringToSign + "]");
    String signature =
        Base64.getEncoder().encodeToString(getSignatureMethod().digest(signingKey(), stringToSign));
    Map<String, String> authParams = filter(new HashMap<String, String>() {
      {
        putAll(oauthParams(timestamp));
        put(OAUTH_SIGNATURE, URLEncoder.encode(signature, StandardCharsets.UTF_8.toString()));
        put(REALM, getRealm());
      }
    });
    return authParams.keySet().stream().map(key -> keyValueWrapped(key, authParams.get(key))).collect(joining(COMMA, "OAuth ", ""));
  }

  private Map<String, String> oauthParams(String timestamp) {
    Map<String, String> authParams = filter(new HashMap<String, String>() {
      {
        put(OAUTH_CONSUMER_KEY, getConsumerKey());
        put(OAUTH_SIGNATURE_METHOD, getSignatureMethod().formalName());
        put(OAUTH_TIMESTAMP, timestamp);
        put(OAUTH_VERSION, getVersion());
        put(OAUTH_NONCE, getNonce());
        put(OAUTH_TOKEN, getAccessToken());
        put(OAUTH_VERIFIER, getVerifier());
      }
    });
    return authParams;
  }

  // 3.4.2. HMAC-SHA1 -> says the & must always be present, so we can just default to "" if null
  private String signingKey() {
    return getConsumerSecret() + AMPERSAND + StringUtils.defaultIfEmpty(getTokenSecret(), "");
  }

  private Map<String, String> filter(Map<String, String> params) {
    if (!getIncludeEmptyParams()) {
      params.values().removeIf(StringUtils::isBlank);
    }
    return params;
  }

  // From section 3.4.1 of RFC 5849
  // The signature base string is a consistent, reproducible concatenation
  // of several of the HTTP request elements into a single string. The
  // string is used as an input to the "HMAC-SHA1" and "RSA-SHA1"
  // signature methods.
  //
  // The signature base string includes the following components of the
  // HTTP request:
  // * The HTTP request method (e.g., "GET", "POST", etc.).
  // * The authority as declared by the HTTP "Host" request header field.
  // * The path and query components of the request resource URI.
  // * The protocol parameters excluding the "oauth_signature".
  //
  // The signature base string is constructed by concatenating together,
  // in order, the following HTTP request elements:
  //
  // 1. The HTTP request method in uppercase. For example: "HEAD",
  // "GET", "POST", etc. If the request uses a custom HTTP method, it
  // MUST be encoded (Section 3.6).
  // 2. An "&" character (ASCII code 38).
  // 3. The base string URI from Section 3.4.1.2, after being encoded
  // (Section 3.6).
  // 4. An "&" character (ASCII code 38).
  // 5. The request parameters as normalized in Section 3.4.1.3.2, after
  // being encoded (Section 3.6).

  // We use a TreeMap so it's sorted; in the RFC the resulting base string appears
  // to be sorted lexically...
  private static String buildStringToSign(String httpMethod, URL url, Map<String, String> params,
      Map<String, String> additionalData) throws Exception {
    Map<String, String> requestParams = new TreeMap<String, String>(CASE_INSENSITIVE_ORDER) {
      {
        putAll(params);
        putAll(additionalData);
      }
    };
    if (url.getQuery() != null) {
      for (String keyValue : url.getQuery().split(AMPERSAND)) {
        String[] p = keyValue.split(EQUALS);
        requestParams.put(p[0], p[1]);
      }
    }
    String paramString = requestParams.keySet().stream().map(key -> keyAndValue(key, requestParams.get(key)))
        .collect(joining(AMPERSAND));
    return httpMethod.toUpperCase() + AMPERSAND
        + URLEncoder.encode(new URL(url.getProtocol(), url.getHost(), url.getPort(), url.getPath()).toString(),
            StandardCharsets.UTF_8.toString())
        + AMPERSAND + URLEncoder.encode(paramString.toString(), StandardCharsets.UTF_8.toString());
  }

  private static final String keyValueWrapped(String key, String value) {
    return keyAndValue(key, alwaysWrap(value, "\""));
  }

  private static final String alwaysWrap(String toWrap, String wrapChar) {
    if (isEmpty(toWrap)) {
      return wrapChar + wrapChar;
    }
    return wrap(toWrap, wrapChar);
  }

  private static final String keyAndValue(String key, String value) {
    return key + EQUALS + value;
  }

  public URL getUrl() {
    return url;
  }

  private void setUrl(URL url) {
    this.url = Args.notNull(url, "url");
  }

  public AuthorizationBuilder withUrl(URL url) {
    setUrl(url);
    return this;
  }

  private String getMethod() {
    return method;
  }

  private void setMethod(String s) {
    method = Args.notBlank(s, "method");
  }

  public AuthorizationBuilder withMethod(String s) {
    setMethod(s);
    return this;
  }

  private String getConsumerKey() {
    return consumerKey;
  }

  private void setConsumerKey(String s) {
    consumerKey = Args.notBlank(s, "consumerKey");
  }

  public AuthorizationBuilder withConsumerKey(String s) {
    setConsumerKey(s);
    return this;
  }

  private String getConsumerSecret() {
    return consumerSecret;
  }

  private void setConsumerSecret(String s) {
    consumerSecret = Args.notBlank(s, "consumerSecret");
  }

  public AuthorizationBuilder withConsumerSecret(String s) {
    setConsumerSecret(s);
    return this;
  }

  private String getAccessToken() {
    return accessToken;
  }

  private void setAccessToken(String s) {
    accessToken = s;
  }

  public AuthorizationBuilder withAccessToken(String s) {
    setAccessToken(s);
    return this;
  }

  private String getTokenSecret() {
    return tokenSecret;
  }

  private void setTokenSecret(String s) {
    tokenSecret = s;
  }

  public AuthorizationBuilder withTokenSecret(String s) {
    setTokenSecret(s);
    return this;
  }

  private String getNonce() {
    return nonce;
  }

  private void setNonce(String s) {
    nonce = Args.notBlank(s, "nonce");
  }

  public AuthorizationBuilder withNonce(String s) {
    setNonce(s);
    return this;
  }

  private String getRealm() {
    return realm;
  }

  private void setRealm(String s) {
    realm = StringUtils.defaultIfBlank(s, "");
  }

  public AuthorizationBuilder withRealm(String s) {
    setRealm(s);
    return this;
  }

  private String getVersion() {
    return version;
  }

  private void setVersion(String s) {
    version = StringUtils.defaultIfBlank(s, "1.0");
  }

  public AuthorizationBuilder withVersion(String s) {
    setVersion(s);
    return this;
  }

  private boolean getIncludeEmptyParams() {
    return includeEmptyParams;
  }

  private void setIncludeEmptyParams(boolean b) {
    includeEmptyParams = b;
  }

  public AuthorizationBuilder withIncludeEmptyParams(boolean b) {
    setIncludeEmptyParams(b);
    return this;
  }

  private SignatureMethod getSignatureMethod() {
    return signatureMethod;
  }

  private void setSignatureMethod(SignatureMethod s) {
    signatureMethod = Args.notNull(s, "signatureMethod");
  }

  public AuthorizationBuilder withSignatureMethod(SignatureMethod m) {
    setSignatureMethod(m);
    return this;
  }

  private String getVerifier() {
    return verifier;
  }

  private void setVerifier(String s) {
    verifier = StringUtils.defaultIfBlank(s, "");
  }

  public AuthorizationBuilder withVerifier(String s) {
    setVerifier(s);
    return this;
  }

  private Map<String, String> getAdditionalData() {
    return additionalData;
  }

  private void setAdditionalData(Map<String, String> data) {
    this.additionalData = ObjectUtils.defaultIfNull(data, new HashMap<>());
  }

  public AuthorizationBuilder withAdditionalData(Map<String, String> data) {
    setAdditionalData(data);
    return this;
  }
}
