/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import jakarta.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import org.owasp.webgoat.container.i18n.PluginMessages;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/** Created by jason on 9/30/17. */
@RestController
public class CSRFGetFlag {

  @Autowired LessonSession userSessionData;
  @Autowired private PluginMessages pluginMessages;

  @PostMapping(
      path = "/csrf/basic-get-flag",
      produces = {"application/json"})
  @ResponseBody
  public Map<String, Object> invoke(HttpServletRequest req) {

    Map<String, Object> response = new HashMap<>();

    // A state changing request is only honoured when it provably came from this
    // application. A forged request from another site carries either no initiator or a
    // foreign one, and is refused here instead of being rewarded.
    if (!RequestOrigin.isSameOrigin(req)) {
      response.put("success", false);
      response.put("message", "Cross origin request rejected");
      response.put("flag", null);
      return response;
    }

    response.put("success", false);
    response.put("message", "Appears the request came from the original host");
    response.put("flag", null);
    return response;
  }
}
