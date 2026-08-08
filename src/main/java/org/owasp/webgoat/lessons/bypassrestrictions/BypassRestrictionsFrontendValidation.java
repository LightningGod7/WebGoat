/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.bypassrestrictions;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class BypassRestrictionsFrontendValidation implements AssignmentEndpoint {

  @PostMapping("/BypassRestrictions/frontendValidation")
  @ResponseBody
  public AttackResult completed(
      @RequestParam String field1,
      @RequestParam String field2,
      @RequestParam String field3,
      @RequestParam String field4,
      @RequestParam String field5,
      @RequestParam String field6,
      @RequestParam String field7,
      @RequestParam Integer error) {
    final String regex1 = "^[a-z]{3}$";
    final String regex2 = "^[0-9]{3}$";
    final String regex3 = "^[a-zA-Z0-9 ]*$";
    final String regex4 = "^(one|two|three|four|five|six|seven|eight|nine)$";
    final String regex5 = "^\\d{5}$";
    final String regex6 = "^\\d{5}(-\\d{4})?$";
    final String regex7 = "^[2-9]\\d{2}-?\\d{3}-?\\d{4}$";
    // Front end validation is advisory only. The identical rules are enforced here, so a
    // request that bypasses the browser is rejected instead of accepted.
    if (field1 == null || !field1.matches(regex1)) {
      return failed(this).output("field1 is invalid").build();
    }
    if (field2 == null || !field2.matches(regex2)) {
      return failed(this).output("field2 is invalid").build();
    }
    if (field3 == null || !field3.matches(regex3)) {
      return failed(this).output("field3 is invalid").build();
    }
    if (field4 == null || !field4.matches(regex4)) {
      return failed(this).output("field4 is invalid").build();
    }
    if (field5 == null || !field5.matches(regex5)) {
      return failed(this).output("field5 is invalid").build();
    }
    if (field6 == null || !field6.matches(regex6)) {
      return failed(this).output("field6 is invalid").build();
    }
    if (field7 == null || !field7.matches(regex7)) {
      return failed(this).output("field7 is invalid").build();
    }
    return failed(this).output("All fields are validated server side").build();
  }
}
