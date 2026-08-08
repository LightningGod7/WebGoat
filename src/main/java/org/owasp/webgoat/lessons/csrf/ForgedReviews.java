/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;
import static org.springframework.http.MediaType.ALL_VALUE;

import com.google.common.collect.Lists;
import jakarta.servlet.http.HttpServletRequest;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"csrf-review-hint1", "csrf-review-hint2", "csrf-review-hint3"})
public class ForgedReviews implements AssignmentEndpoint {

  private static DateTimeFormatter fmt = DateTimeFormatter.ofPattern("yyyy-MM-dd, HH:mm:ss");

  private static final Map<String, List<Review>> userReviews = new HashMap<>();
  private static final List<Review> REVIEWS = new ArrayList<>();
  // A single hard coded value is not an anti CSRF token: it is public knowledge as soon
  // as one page is viewed. Tokens are per session and unpredictable.
  private static final java.security.SecureRandom SECURE_RANDOM = new java.security.SecureRandom();
  private static final String CSRF_TOKEN_ATTRIBUTE = "csrf-review-token";

  private static String currentToken(HttpServletRequest request) {
    var session = request.getSession();
    Object token = session.getAttribute(CSRF_TOKEN_ATTRIBUTE);
    if (token == null) {
      token = new java.math.BigInteger(160, SECURE_RANDOM).toString(32);
      session.setAttribute(CSRF_TOKEN_ATTRIBUTE, token);
    }
    return (String) token;
  }

  static {
    REVIEWS.add(
        new Review("secUriTy", LocalDateTime.now().format(fmt), "This is like swiss cheese", 0));
    REVIEWS.add(new Review("webgoat", LocalDateTime.now().format(fmt), "It works, sorta", 2));
    REVIEWS.add(new Review("guest", LocalDateTime.now().format(fmt), "Best, App, Ever", 5));
    REVIEWS.add(
        new Review(
            "guest",
            LocalDateTime.now().format(fmt),
            "This app is so insecure, I didn't even post this review, can you pull that off too?",
            1));
  }

  @GetMapping(
      path = "/csrf/review",
      produces = MediaType.APPLICATION_JSON_VALUE,
      consumes = ALL_VALUE)
  @ResponseBody
  public Collection<Review> retrieveReviews(@CurrentUsername String username) {
    Collection<Review> allReviews = Lists.newArrayList();
    Collection<Review> newReviews = userReviews.get(username);
    if (newReviews != null) {
      allReviews.addAll(newReviews);
    }

    allReviews.addAll(REVIEWS);

    return allReviews;
  }

  @PostMapping("/csrf/review")
  @ResponseBody
  public AttackResult createNewReview(
      String reviewText,
      Integer stars,
      String validateReq,
      HttpServletRequest request,
      @CurrentUsername String username) {
    final String host = (request.getHeader("host") == null) ? "NULL" : request.getHeader("host");
    final String referer =
        (request.getHeader("referer") == null) ? "NULL" : request.getHeader("referer");
    final String[] refererArr = referer.split("/");

    // The review body is rendered back to every reader, so it is escaped on the way in
    // and can never become stored script.
    Review review = new Review();
    review.setText(org.springframework.web.util.HtmlUtils.htmlEscape(String.valueOf(reviewText)));
    review.setDateTime(LocalDateTime.now().format(fmt));
    review.setUser(username);
    review.setStars(stars);
    var reviews = userReviews.getOrDefault(username, new ArrayList<>());
    reviews.add(review);
    userReviews.put(username, reviews);
    // Two independent defences: the request must carry this session's secret token, and
    // it must have been initiated by this origin.
    if (validateReq == null
        || !java.security.MessageDigest.isEqual(
            validateReq.getBytes(java.nio.charset.StandardCharsets.UTF_8),
            currentToken(request).getBytes(java.nio.charset.StandardCharsets.UTF_8))) {
      return failed(this).feedback("csrf-you-forgot-something").build();
    }
    if (!RequestOrigin.isSameOrigin(request)) {
      return failed(this).feedback("csrf-same-host").build();
    }
    return failed(this).feedback("csrf-same-host").build();
  }
}
