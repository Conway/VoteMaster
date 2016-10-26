function success(message) {
    $.alert({content:message, title:"Success!", backgroundDismiss:true, confirmKeys:[13], cancelKeys:[27]});
}
$(document).ready(function() {
    $('.disable').click(function() {
        var val = $(this).closest('tr').children('td:eq(0)').text();
        $.ajax({
            url: '/api/disable_admin',
            type: 'GET',
            data: {
                'id': val
            },
            success: success("Admin disabled")
        });
        $(this).prop('disabled', true);
    });
});
$(document).ready(function() {
    $('.enable').click(function(event) {
        var val = $(this).closest('tr').children('td:eq(0)').text();
        $.ajax({
            url: '/api/enable_admin',
            type: 'GET',
            data: {
                id: val
            },
            success: success("Admin enabled")
        });
        $(this).prop('disabled', true);
    });
});
$(document).ready(function() {
    $('.lead-admin').click(function() {
        var val = $(this).closest('tr').children('td:eq(0)').text();
        $.ajax({
            url: '/api/change_admin_role',
            type: 'GET',
            data: {
                'id': val,
                'role': 'lead'
            },
            success: success("Admin role changed")
        });
        $(this).prop('disabled', true);
    });
});
$(document).ready(function() {
    $('.normal-admin').click(function() {
        var val = $(this).closest('tr').children('td:eq(0)').text();
        $.ajax({
            url: '/api/change_admin_role',
            type: 'GET',
            data: {
                'id': val,
                'role': 'normal'
            },
            success: success("Admin role changed")
        });
        $(this).prop('disabled', true);
    });
});
$(document).ready(function() {
    $('.observer-admin').click(function() {
        var val = $(this).closest('tr').children('td:eq(0)').text();
        $.ajax({
            url: '/api/change_admin_role',
            type: 'GET',
            data: {
                'id': val,
                'role': 'observer'
            },
            success: success("Admin role changed")
        });
        $(this).prop('disabled', true);
    });
});
$(document).ready(function() {
    $('.disable_otp').click(function() {
        var val = $(this).closest('tr').children('td:eq(0)').text();
        $.ajax({
            url: '/api/disable_2fa',
            type: 'GET',
            data: {
                'id': val
            },
            success: success("2FA disabled for this admin")
        });
        $(this).prop('disabled', true);
    });
});