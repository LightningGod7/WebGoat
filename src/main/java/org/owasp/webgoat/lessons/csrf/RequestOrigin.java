/*
 * SPDX-FileCopyrightText: Copyright © 2024 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Helper used by the CSRF lessons to decide whether a state changing request really originated
 * from this application.
 *
 * <p>A cross site request forgery is a request that the browser sends with the victim's ambient
 * credentials but that was initiated by a page the application does not control. The Origin
 * header (and, as a fallback, Referer) tells us which document initiated the request, and unlike
 * a cookie it cannot be set by the attacker's page. A request whose initiator is absent or does
 * not match this host is therefore rejected.
 */
public final class RequestOrigin {

  private RequestOrigin() {}

  /** Returns true only when the request demonstrably came from this same origin. */
  public static boolean isSameOrigin(HttpServletRequest request) {
    if (request == null) {
      return false;
    }
    String host = request.getHeader("Host");
    if (host == null || host.isBlank()) {
      return false;
    }
    String initiator = request.getHeader("Origin");
    if (initiator == null || initiator.isBlank()) {
      initiator = request.getHeader("Referer");
    }
    // No initiator at all: refuse rather than fall through, otherwise stripping the header
    // is itself the bypass.
    if (initiator == null || initiator.isBlank()) {
      return false;
    }
    String initiatorHost = hostOf(initiator);
    return initiatorHost != null && initiatorHost.equalsIgnoreCase(host);
  }

  private static String hostOf(String url) {
    try {
      return new java.net.URI(url).getAuthority();
    } catch (Exception e) {
      return null;
    }
  }
}
