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
public class BypassRestrictionsFieldRestrictions implements AssignmentEndpoint {

  @PostMapping("/BypassRestrictions/FieldRestrictions")
  @ResponseBody
  public AttackResult completed(
      @RequestParam String select,
      @RequestParam String radio,
      @RequestParam String checkbox,
      @RequestParam String shortInput,
      @RequestParam String readOnlyInput) {
    // Client side field restrictions are only a convenience. Every one of them is now
    // re-applied on the server, so a hand crafted request cannot exceed them.
    if (!"option1".equals(select) && !"option2".equals(select)) {
      return failed(this).output("Invalid value for select").build();
    }
    if (!"option1".equals(radio) && !"option2".equals(radio)) {
      return failed(this).output("Invalid value for radio").build();
    }
    if (!"on".equals(checkbox) && !"off".equals(checkbox)) {
      return failed(this).output("Invalid value for checkbox").build();
    }
    if (shortInput == null || shortInput.length() > 5) {
      return failed(this).output("Input is too long").build();
    }
    if (!"readonly".equals(readOnlyInput)) {
      return failed(this).output("Read only field was modified").build();
    }
    return failed(this).output("All restrictions are enforced server side").build();
  }
}
