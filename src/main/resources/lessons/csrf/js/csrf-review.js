$(document).ready(function () {
//    $("#postReview").on("click", function () {
//        var commentInput = $("#reviewInput").val();
//        $.ajax({
//            type: 'POST',
//            url: 'csrf/review',
//            data: JSON.stringify({text: commentInput}),
//            contentType: "application/json",
//            dataType: 'json'
//        }).then(
//            function () {
//                getChallenges();
//                $("#commentInput").val('');
//            }
//        )
//    });

    var html = '<li class="comment">' +
        '<div class="pull-left">' +
        '<img class="avatar" src="images/avatar1.png" alt="avatar"/>' +
        '</div>' +
        '<div class="comment-body">' +
        '<div class="comment-heading">' +
        '<h4 class="user">USER / STARS stars</h4>' +
        '<h5 class="time">DATETIME</h5>' +
        '</div>' +
        '<p>COMMENT</p>' +
        '</div>' +
        '</li>';

    // Review content is supplied by other users. Interpolating it into an HTML string
    // executes whatever markup they stored, so every value is escaped to text first.
    function escapeHtml(value) {
        return $('<div>').text(value === null || value === undefined ? '' : value).html();
    }

    getChallenges();

    function getChallenges() {
        $("#list").empty();
        $.get('csrf/review', function (result, status) {
            for (var i = 0; i < result.length; i++) {
                var comment = html.replace('USER', escapeHtml(result[i].user));
                comment = comment.replace('DATETIME', escapeHtml(result[i].dateTime));
                comment = comment.replace('COMMENT', escapeHtml(result[i].text));
                comment = comment.replace('STARS', escapeHtml(result[i].stars))
                $("#list").append(comment);
            }

        });
    }
})
