/**
 * Generating Authorization headers as per
 * <a href="https://tools.ietf.org/html/rfc5849">RFC5849</a>.
 * <p>
 * This has been verified to work with NetSuite OAUTH 1.0 (using HMAC-SHA1), but not any other
 * providers.
 * </p>
 *
 */
package com.adaptris.core.oauth.rfc5849;