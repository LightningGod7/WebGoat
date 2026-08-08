/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.mitigation;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.lessons.sqlinjection.advanced.SqlInjectionLesson6a;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints(
    value = {"SqlOnlyInputValidation-1", "SqlOnlyInputValidation-2", "SqlOnlyInputValidation-3"})
public class SqlOnlyInputValidation implements AssignmentEndpoint {

  private final SqlInjectionLesson6a lesson6a;

  public SqlOnlyInputValidation(SqlInjectionLesson6a lesson6a) {
    this.lesson6a = lesson6a;
  }

  @PostMapping("/SqlOnlyInputValidation/attack")
  @ResponseBody
  public AttackResult attack(@RequestParam("userid_sql_only_input_validation") String userId) {
    // Input validation is a defence in depth measure, not the control: the identifier is
    // constrained to the expected type before it ever reaches the data layer.
    if (userId == null || !userId.matches("[0-9]{1,12}")) {
      return failed(this).feedback("SqlOnlyInputValidation-failed").build();
    }

    AttackResult attackResult = lesson6a.injectableQuery(userId);
    return new AttackResult(
        attackResult.isLessonCompleted(),
        attackResult.getFeedback(),
        attackResult.getFeedbackArgs(),
        attackResult.getOutput(),
        attackResult.getOutputArgs(),
        getClass().getSimpleName(),
        true);
  }
}
