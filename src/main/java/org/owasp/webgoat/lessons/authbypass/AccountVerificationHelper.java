/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.authbypass;

import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/** Created by appsec on 7/18/17. */
public class AccountVerificationHelper {

  // simulating database storage of verification credentials
  private static final Integer verifyUserId = 1223445;
  private static final Map<String, String> userSecQuestions = new HashMap<>();

  static {
    userSecQuestions.put("secQuestion0", "Dr. Watson");
    userSecQuestions.put("secQuestion1", "Baker Street");
  }

  private static final Map<Integer, Map> secQuestionStore = new HashMap<>();

  static {
    secQuestionStore.put(verifyUserId, userSecQuestions);
  }

  // end 'data store set up'

  // this is to aid feedback in the attack process and is not intended to be part of the
  // 'vulnerable' code
  public boolean didUserLikelylCheat(HashMap<String, String> submittedAnswers) {
    return false;
  }

  /**
   * Verification requires the account to exist, the submitted answer set to match the stored set
   * exactly, and every stored answer to be present and correct. Omitting or renaming a question can
   * no longer skip a check.
   */
  public boolean verifyAccount(Integer userId, HashMap<String, String> submittedQuestions) {
    if (userId == null || submittedQuestions == null) {
      return false;
    }
    Map<String, String> stored = secQuestionStore.get(userId);
    if (stored == null) {
      return false;
    }
    if (!submittedQuestions.keySet().equals(stored.keySet())) {
      return false;
    }
    for (Map.Entry<String, String> entry : stored.entrySet()) {
      String submitted = submittedQuestions.get(entry.getKey());
      if (submitted == null || !MessageDigest.isEqual(
              submitted.getBytes(StandardCharsets.UTF_8),
              entry.getValue().getBytes(StandardCharsets.UTF_8))) {
        return false;
      }
    }
    return true;
  }
}
