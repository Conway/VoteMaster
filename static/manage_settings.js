function success(message) {
    $.alert({
        content: message,
        title: "Success!",
        backgroundDismiss: true,
        confirmKeys: [13],
        cancelKeys: [27]
    });
}
$(document).ready(function() {
    $('#close').click(function() {
        var val = $(this).closest('tr').children('td:eq(0)').text();
        $.ajax({
            url: '/api/close_vote',
            type: 'GET',
            success: success("Vote Closed")
        });
        $(this).prop('disabled', true);
    });
});
$(document).ready(function() {
    $('#open').click(function() {
        var val = $(this).closest('tr').children('td:eq(0)').text();
        $.ajax({
            url: '/api/open_vote',
            type: 'GET',
            success: success("Vote Opened")
        });
        $(this).prop('disabled', true);
    });
});