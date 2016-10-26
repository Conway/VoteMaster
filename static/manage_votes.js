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
    $('.uncount').click(function() {
        var val = $(this).closest('tr').children('td:eq(0)').text();
        $.get('/api/disable_vote?id=' + val, success("Vote disabled"));
    });
});
$(document).ready(function() {
    $('.count').click(function() {
        var val = $(this).closest('tr').children('td:eq(0)').text();
        $.get('/api/enable_vote?id=' + val, success("Vote enabled"));
    });
});