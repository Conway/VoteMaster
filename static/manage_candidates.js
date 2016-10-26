function success(message) {
    $.alert({content:message, title:"Success!", backgroundDismiss:true, confirmKeys:[13], cancelKeys:[27]});
}
$(document).ready(function() {
    $('.disable').click(function() {
        var val = $(this).closest('tr').children('td:eq(0)').text();
        $.ajax({
            url: '/api/lock_option',
            type: 'GET',
            data: {
                'id': val
            },
            success: success("Option disabled")
        });
        $(this).prop('disabled', true);
    });
});
$(document).ready(function() {
    $('.enable').click(function(event) {
        var val = $(this).closest('tr').children('td:eq(0)').text();
        $.ajax({
            url: '/api/unlock_option',
            type: 'GET',
            data: {
                id: val
            },
            success: success("Option enabled")
        });
        $(this).prop('disabled', true);
    });
});
$(document).ready(function() {
    $('#save').click(function() {
        var name = $("#optionname").val();
        var description = $("#description").val();
        $("#optiontable tbody").append('<tr><td>?</td><td>' + name + '</td><td>0</td><td>True</td><td>(Refresh to access actions)</td></tr>');
        $.ajax({
            url: '/api/create_option',
            type: 'GET',
            data: {
                name: name,
                description: description
            },
            success: success("Option created (refresh to see all option data).")
        });
        $("#description").val("Description");
        $("#optionname").val("");
    });
});