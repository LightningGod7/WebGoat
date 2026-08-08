/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges.challenge7;

import java.security.SecureRandom;
import java.util.Random;

/**
 * WARNING: DO NOT CHANGE FILE WITHOUT CHANGING .git contents
 *
 * @author nbaars
 * @since 8/17/17.
 */
public class PasswordResetLink {

  public String createPasswordReset(String username, String key) {
    // A reset token must be unpredictable and must not be derived from the account name.
    // Seeding a non cryptographic generator with a known value made the administrator's
    // link reproducible by anyone able to read this code.
    byte[] token = new byte[20];
    new SecureRandom().nextBytes(token);
    StringBuilder sb = new StringBuilder(token.length * 2);
    for (byte b : token) {
      sb.append(String.format("%02x", b));
    }
    return sb.toString();
  }

  public static String scramble(Random random, String inputString) {
    char[] a = inputString.toCharArray();
    for (int i = 0; i < a.length; i++) {
      int j = random.nextInt(a.length);
      char temp = a[i];
      a[i] = a[j];
      a[j] = temp;
    }
    return new String(a);
  }

  public static void main(String[] args) {
    if (args == null || args.length != 2) {
      System.out.println("Need a username and key");
      System.exit(1);
    }
    String username = args[0];
    String key = args[1];
    System.out.println("Generation password reset link for " + username);
    System.out.println(
        "Created password reset link: "
            + new PasswordResetLink().createPasswordReset(username, key));
  }
}
