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

import java.net.URL;
import java.nio.charset.StandardCharsets;
import javax.validation.constraints.NotBlank;
import org.apache.commons.codec.digest.HmacAlgorithms;
import org.apache.commons.codec.digest.HmacUtils;
import org.apache.commons.lang3.BooleanUtils;
import org.apache.commons.lang3.StringUtils;
import com.adaptris.annotation.AdvancedConfig;
import com.adaptris.annotation.ComponentProfile;
import com.adaptris.annotation.DisplayOrder;
import com.adaptris.annotation.InputFieldDefault;
import com.adaptris.annotation.InputFieldHint;
import com.adaptris.core.AdaptrisMessage;
import com.adaptris.core.util.Args;
import com.adaptris.interlok.resolver.ExternalResolver;
import com.adaptris.security.password.Password;
import com.thoughtworks.xstream.annotations.XStreamAlias;

/**
 * Captures authorization data for building the RFC5849 Authorization header.
 *
 * @config oauth-rfc5849-authorization-data
 */
@XStreamAlias("oauth-rfc5849-authorization-data")
@DisplayOrder(order =
{
    "accessToken", "tokenSecret", "consumerKey", "consumerSecret", "signatureMethod", "nonce", "realm", "version"
})
@ComponentProfile(since = "3.8.4", summary = "Captures authorization data for building the RFC5849 Authorization header", tag = "oauth,oauthv1,http,https")
public class AuthorizationData {
  /**
   * Maps to {@code oauth_signature_method}
   *
   */
  public static enum SignatureMethod {
    /**
     * {@code PLAINTEXT}.
     *
     */
    PLAIN_TEXT("PLAINTEXT") {
      @Override
      public byte[] digest(String key, String valueToDigest) throws Exception {
        return key.getBytes(StandardCharsets.UTF_8.name());
      }
    },
    /**
     * {@code HMAC-MD5}.
     *
     */
    HMAC_MD5("HMAC-MD5") {
      @Override
      public byte[] digest(String key, String valueToDigest) {
        return new HmacUtils(HmacAlgorithms.HMAC_MD5, key).hmac(valueToDigest);
      }
    },
    /**
     * {@code HMAC-SHA1}.
     *
     */
    HMAC_SHA1("HMAC-SHA1") {
      @Override
      public byte[] digest(String key, String valueToDigest) {
        return new HmacUtils(HmacAlgorithms.HMAC_SHA_1, key).hmac(valueToDigest);
      }
    },
    /**
     * {@code HMAC-SHA256}.
     *
     */
    HMAC_SHA256("HMAC-SHA256") {
      @Override
      public byte[] digest(String key, String valueToDigest) {
        return new HmacUtils(HmacAlgorithms.HMAC_SHA_256, key).hmac(valueToDigest);
      }
    },
    /**
     * {@code HMAC-SHA384}.
     *
     */
    HMAC_SHA384("HMAC-SHA384") {
      @Override
      public byte[] digest(String key, String valueToDigest) {
        return new HmacUtils(HmacAlgorithms.HMAC_SHA_384, key).hmac(valueToDigest);
      }
    },
    /**
     * {@code HMAC-SHA512}.
     *
     */

    HMAC_SHA512("HMAC-SHA512") {
      @Override
      public byte[] digest(String key, String valueToDigest) {
        return new HmacUtils(HmacAlgorithms.HMAC_SHA_256, key).hmac(valueToDigest);
      }
    };
    private String formalName;

    SignatureMethod(String s) {
      formalName = s;
    }

    public abstract byte[] digest(String key, String valueToDigest) throws Exception;

    public String formalName() {
      return formalName.toUpperCase();
    }
  };


  @InputFieldHint(expression = true)
  @NotBlank
  private String consumerKey;
  @InputFieldHint(expression = true, external = true, style = "PASSWORD")
  @NotBlank
  private String consumerSecret;
  @InputFieldHint(expression = true)
  private String accessToken;
  @InputFieldHint(expression = true, external = true, style = "PASSWORD")
  private String tokenSecret;
  @InputFieldHint(expression = true,
  style = "com.adaptris.core.oauth.rfc5849.AuthorizationData.SignatureMethod")
  @InputFieldDefault(value = "HMAC_SHA1")
  private String signatureMethod;
  @InputFieldHint(expression = true)
  @AdvancedConfig
  @InputFieldDefault(value = "generated from the message unique-id")
  private String nonce;
  @InputFieldHint(expression = true)
  @AdvancedConfig
  private String realm;
  @InputFieldDefault(value = "1.0")
  @AdvancedConfig
  private String version;
  @InputFieldDefault(value = "false")
  @AdvancedConfig
  private Boolean includeEmptyParams;
  @AdvancedConfig
  private String verifier;

  public AuthorizationData() {
  }

  public AuthorizationBuilder builder(AdaptrisMessage msg) throws Exception {
    String nonceToUse = StringUtils.defaultIfEmpty(msg.resolve(getNonce()),
        msg.getUniqueId().replaceAll(":", "").replaceAll("-", ""));
    return new AuthorizationBuilder().withAccessToken(msg.resolve(getAccessToken()))
        .withConsumerKey(msg.resolve(getConsumerKey()))
        .withConsumerSecret(
            Password.decode(msg.resolve(ExternalResolver.resolve(getConsumerSecret()))))
        .withIncludeEmptyParams(includeEmptyParams()).withNonce(nonceToUse)
        .withRealm(msg.resolve(getRealm()))
        .withSignatureMethod(signatureMethod(msg))
        .withTokenSecret(Password.decode(msg.resolve(ExternalResolver.resolve(getTokenSecret()))))
        .withVerifier(msg.resolve(getVerifier()))
        .withVersion(version());
  }

  public AuthorizationBuilder builder(String method, URL url, AdaptrisMessage msg)
      throws Exception {
    return builder(msg).withMethod(method).withUrl(url);
  }


  protected SignatureMethod signatureMethod(AdaptrisMessage msg) {
    String method = msg.resolve(getSignatureMethod());
    for (SignatureMethod m : SignatureMethod.values()) {
      if (m.formalName().equalsIgnoreCase(method) || m.name().equalsIgnoreCase(method)) {
        return m;
      }
    }
    return SignatureMethod.HMAC_SHA1;
  }


  public String getConsumerKey() {
    return consumerKey;
  }

  /**
   * Set the {@code oauth_consumer_key}.
   *
   */
  public void setConsumerKey(String s) {
    consumerKey = Args.notBlank(s, "consumerKey");
  }

  public String getConsumerSecret() {
    return consumerSecret;
  }

  /**
   * Set the consumer secret that proves your ownership of the key.
   *
   */
  public void setConsumerSecret(String s) {
    consumerSecret = Args.notBlank(s, "consumerSecret");
  }

  public String getAccessToken() {
    return accessToken;
  }

  /**
   * Set the {@code oauth_token}.
   *
   */
  public void setAccessToken(String s) {
    accessToken = Args.notBlank(s, "accessToken");
  }

  public String getTokenSecret() {
    return tokenSecret;
  }

  /**
   * Set the token secret that proves your ownership of the token.
   *
   */
  public void setTokenSecret(String s) {
    tokenSecret = Args.notBlank(s, "tokenSecret");
  }

  public String getNonce() {
    return nonce;
  }

  /**
   * Set the {@code oauth_nonce}
   *
   * @param nonce if not specified, then one will be generated.
   */
  public void setNonce(String nonce) {
    this.nonce = nonce;
  }

  public String getRealm() {
    return realm;
  }

  /**
   * Set the realm.
   *
   */
  public void setRealm(String realm) {
    this.realm = realm;
  }

  public String getVersion() {
    return version;
  }

  /**
   * Set {@code oauth_version}.
   *
   */
  public void setVersion(String version) {
    this.version = version;
  }

  public String version() {
    return StringUtils.defaultIfEmpty(getVersion(), "1.0");
  }

  public Boolean getIncludeEmptyParams() {
    return includeEmptyParams;
  }

  /**
   * Specify whether empty fields are included for the purposes of a signature.
   * <p>
   * Some servers require empty parameters to be added to the signature; set this to be true if that
   * is required.
   * </p>
   *
   * @param b true to include empty fields in the authorization data.
   */
  public void setIncludeEmptyParams(Boolean b) {
    includeEmptyParams = b;
  }

  public boolean includeEmptyParams() {
    return BooleanUtils.toBooleanDefaultIfNull(getIncludeEmptyParams(), false);
  }

  public String getSignatureMethod() {
    return signatureMethod;
  }

  /**
   * Set the signature Method.
   *
   * @param s the signature method; HMAC-SHA1 if not specified
   */
  public void setSignatureMethod(String s) {
    signatureMethod = s;
  }

  public String getVerifier() {
    return verifier;
  }


  /**
   * Set the {@code oauth_verifier}.
   *
   */
  public void setVerifier(String v) {
    verifier = v;
  }
}
