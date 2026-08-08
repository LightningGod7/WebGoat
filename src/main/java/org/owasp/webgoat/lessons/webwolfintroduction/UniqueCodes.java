/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.webwolfintroduction;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

/**
 * Holds the one time code that is mailed to a user.
 *
 * <p>A verification code is a credential. Deriving it from the account name, as a reversed
 * username, meant any party who knew the name also knew the code and never needed to receive the
 * message at all. Codes are therefore drawn from a CSPRNG, kept server side, and compared in
 * constant time.
 */
@Component
public class UniqueCodes {

  private static final SecureRandom RANDOM = new SecureRandom();

  private final Map<String, String> codes = new ConcurrentHashMap<>();

  /** Returns the code for this user, minting an unpredictable one on first use. */
  public String getCode(String username) {
    if (username == null) {
      return null;
    }
    return codes.computeIfAbsent(username, u -> new BigInteger(130, RANDOM).toString(32));
  }

  /** Verifies a presented code without leaking the expected value through timing. */
  public boolean matches(String username, String presentedCode) {
    if (username == null || presentedCode == null) {
      return false;
    }
    String expected = codes.get(username);
    if (expected == null) {
      return false;
    }
    return MessageDigest.isEqual(
        expected.getBytes(StandardCharsets.UTF_8), presentedCode.getBytes(StandardCharsets.UTF_8));
  }
}
