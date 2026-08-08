/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.htmltampering;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"hint1", "hint2", "hint3"})
public class HtmlTamperingTask implements AssignmentEndpoint {

  @PostMapping("/HtmlTampering/task")
  @ResponseBody
  public AttackResult completed(@RequestParam String QTY, @RequestParam String Total) {
    // Price and total are business data: they are recomputed from the server side unit
    // price and never taken from the form, so editing the HTML changes nothing.
    final java.math.BigDecimal unitPrice = new java.math.BigDecimal("2999.99");
    final int quantity;
    try {
      quantity = Integer.parseInt(QTY.trim());
    } catch (NumberFormatException e) {
      return failed(this).feedback("html-tampering.tamper.failure").build();
    }
    if (quantity < 1) {
      return failed(this).feedback("html-tampering.tamper.failure").build();
    }
    java.math.BigDecimal authoritativeTotal = unitPrice.multiply(java.math.BigDecimal.valueOf(quantity));
    return failed(this)
        .feedback("html-tampering.tamper.failure")
        .output("Order total is " + authoritativeTotal.toPlainString())
        .build();
  }
}
