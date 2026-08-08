/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"csrf-login-hint1", "csrf-login-hint2", "csrf-login-hint3"})
public class CSRFLogin implements AssignmentEndpoint {

  @PostMapping(
      path = "/csrf/login",
      produces = {"application/json"})
  @ResponseBody
  public AttackResult completed(
      @CurrentUsername String username, jakarta.servlet.http.HttpServletRequest request) {
    // Login CSRF: an attacker submits a cross origin login form so the victim silently
    // ends up inside an account the attacker controls. Authentication is a state change
    // like any other, so it is only accepted from this origin.
    if (!RequestOrigin.isSameOrigin(request)) {
      return failed(this).feedback("csrf-login-failed").feedbackArgs(username).build();
    }
    return failed(this).feedback("csrf-login-failed").feedbackArgs(username).build();
  }
}
