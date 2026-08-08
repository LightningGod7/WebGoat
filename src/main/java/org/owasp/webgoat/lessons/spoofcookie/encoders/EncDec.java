/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.spoofcookie.encoders;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.security.crypto.codec.Hex;

/***
 *
 * @author Angel Olle Blazquez
 *
 */
public class EncDec {

  private static final String MAC_ALGORITHM = "HmacSHA256";

  /**
   * The value carried by an authentication cookie is public: encoding it is not a security
   * control. The cookie is therefore authenticated with a keyed MAC over a server side secret
   * that never leaves the process, so a client cannot mint a cookie for another identity.
   */
  private static final SecretKeySpec KEY = generateKey();

  private EncDec() {}

  private static SecretKeySpec generateKey() {
    byte[] key = new byte[32];
    new SecureRandom().nextBytes(key);
    return new SecretKeySpec(key, MAC_ALGORITHM);
  }

  private static String mac(final String value) {
    try {
      Mac mac = Mac.getInstance(MAC_ALGORITHM);
      mac.init(KEY);
      return new String(Hex.encode(mac.doFinal(value.getBytes(StandardCharsets.UTF_8))));
    } catch (java.security.GeneralSecurityException e) {
      throw new IllegalStateException("Unable to authenticate cookie value", e);
    }
  }

  public static String encode(final String value) {
    if (value == null) {
      return null;
    }
    String payload = value.toLowerCase();
    return base64Encode(payload + "|" + mac(payload));
  }

  public static String decode(final String encodedValue) throws IllegalArgumentException {
    if (encodedValue == null) {
      return null;
    }

    String decoded = base64Decode(encodedValue);
    int separator = decoded.lastIndexOf('|');
    if (separator < 0) {
      throw new IllegalArgumentException("Invalid cookie");
    }

    String payload = decoded.substring(0, separator);
    byte[] presented = decoded.substring(separator + 1).getBytes(StandardCharsets.UTF_8);
    byte[] expected = mac(payload).getBytes(StandardCharsets.UTF_8);

    // Constant time comparison: a byte at a time comparison would leak the expected tag.
    if (!MessageDigest.isEqual(presented, expected)) {
      throw new IllegalArgumentException("Invalid cookie");
    }
    return payload;
  }

  private static String base64Encode(final String value) {
    return Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8));
  }

  private static String base64Decode(final String value) {
    byte[] decoded = Base64.getDecoder().decode(value.getBytes(StandardCharsets.UTF_8));
    return new String(decoded, StandardCharsets.UTF_8);
  }
}
