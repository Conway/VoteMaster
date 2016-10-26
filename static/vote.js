function modal_alert(message) {
    $.alert({
        content: message,
        title: "Information",
        backgroundDismiss: true,
        confirmKeys: [13],
        cancelKeys: [27],
    });
}

function success(message) {
    $.alert({
        content: message,
        title: "Success!",
        backgroundDismiss: true,
        confirmKeys: [13],
        cancelKeys: [27],
    });
}


$(document).ready(function() {
    $(".description-a").click(function(e) {
        var a = $(this);
        var id = a.attr('id').substring(7);
        var text = $("#desc-" + id);
        modal_alert(text.val());
    });
});

$(document).ready(function() {
    $('#submit').click(function() {
        var selected = '';
        var selected_num = 0;
        //adapted from http://www.jqueryfaqs.com/Articles/Get-values-of-all-checked-checkboxes-by-class-name-using-jQuery.aspx
        $("input:checkbox[class=single-checkbox]:checked").each(function() {
            selected += $(this).attr("id") + ',';
            selected_num += 1;
        });
        if (selected_num != limit) {
            modal_alert("Sorry, " + limit + " options must be selected to submit your vote.");
        } else {
            $.ajax({
                url: '/api/record_vote',
                type: 'GET',
                data: {
                    'choices': selected
                },
                success: $(location).attr('href', '/success')
            });
        }
    });
});
//Source: http://stackoverflow.com/questions/19001844/how-to-limit-the-number-of-selected-checkboxes, among other StackOverflow sources
$(document).ready(function() {
    $("input[name='options']").on('click', function(evt) {;
        if ($("input[name='options']:checked").length > limit) {
            this.checked = false;
            $.alert({
                content: "Sorry, only " + limit + " options can be selected",
                title: "Error!",
                backgroundDismiss: true
            });
        }
    });
});
