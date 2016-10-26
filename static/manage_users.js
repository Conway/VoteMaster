function success(message) {
    $.alert({content:message, title:"Success!", backgroundDismiss:true, confirmKeys:[13], cancelKeys:[27]});
}
$(document).ready(function() {
    $('.disable').click(function() {
        var val = $(this).closest('tr').children('td:eq(0)').text();
        $.ajax({
            url: '/api/lock_user',
            type: 'GET',
            data: {
                'id': val
            },
            success: success("User locked")
        });
        $(this).prop('disabled', true);
    });
});
$(document).ready(function() {
    $('.enable').click(function(event) {
        var val = $(this).closest('tr').children('td:eq(0)').text();
        $.ajax({
            url: '/api/unlock_user',
            type: 'GET',
            data: {
                id: val
            },
            success: success("User unlocked")
        });
        $(this).prop('disabled', true);
    });
});
$(document).ready(function() {
    $('#email-submit').click(function() {
        var email = $("#email").val();
        $("#usertable tbody").append('<tr><td>?</td><td>' + email + '</td><td>?</td><td>No</td><td>No</td><td>(Refresh to access actions)</td></tr>');
        $.ajax({
            url: '/api/invite_user',
            type: 'GET',
            data: {
                email: email,
                send_email: true
            },
            success: success("User invited")
        });
        $("#email").val("");
    });
});
$(document).ready(function() {
    $('#upload-submit').click(function() {
        var form_data = new FormData($('#upload-file')[0]);
        $.ajax({
            type: 'POST',
            url: '/api/bulk_invite',
            data: form_data,
            contentType: false,
            cache: false,
            processData: false,
            async: false,
            success: success("File Successfully Uploaded.\nRefresh to see new users.")
        });
    });
});