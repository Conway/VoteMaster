function note_success() {
    $.alert({
        content: "Notes were saved.",
        title: "Success!",
        backgroundDismiss: true,
        confirmKeys: [13],
        cancelKeys: [27]
    });
}
$(document).ready(function() {
    $('#notes-save').click(function() {
        var text = $("#notes-textarea").val();
        $.ajax({
            url: '/api/update_note',
            type: 'GET',
            data: {
                text: text
            },
            success: note_success()
        });
    });
});