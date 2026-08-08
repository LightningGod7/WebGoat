/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.idor;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
  "idor.hints.otherProfile1",
  "idor.hints.otherProfile2",
  "idor.hints.otherProfile3",
  "idor.hints.otherProfile4",
  "idor.hints.otherProfile5",
  "idor.hints.otherProfile6",
  "idor.hints.otherProfile7",
  "idor.hints.otherProfile8",
  "idor.hints.otherProfile9"
})
public class IDOREditOtherProfile implements AssignmentEndpoint {

  private final LessonSession userSessionData;

  public IDOREditOtherProfile(LessonSession lessonSession) {
    this.userSessionData = lessonSession;
  }

  @PutMapping(path = "/IDOR/profile/{userId}", consumes = "application/json")
  @ResponseBody
  public AttackResult completed(
      @PathVariable("userId") String userId, @RequestBody UserProfile userSubmittedProfile) {

    String authUserId = (String) userSessionData.getValue("idor-authenticated-user-id");

    // Horizontal access control: the caller may only edit their own profile. The id in the
    // path AND the id in the body must both match the authenticated user.
    if (authUserId == null
        || !authUserId.equals(userId)
        || userSubmittedProfile.getUserId() == null
        || !userSubmittedProfile.getUserId().equals(authUserId)) {
      return failed(this).feedback("idor.edit.profile.failure4").build();
    }

    UserProfile currentUserProfile = new UserProfile(authUserId);
    // Only non privileged attributes are accepted from the request body. "role" is
    // authorization data and is never taken from user input (mass assignment).
    currentUserProfile.setColor(userSubmittedProfile.getColor());
    userSessionData.setValue("idor-updated-own-profile", currentUserProfile);

    return failed(this)
        .feedback("idor.edit.profile.failure3")
        .output(currentUserProfile.profileToMap().toString())
        .build();
  }
}
