// SpiderFoot scan info page logic.

var scanId, scanStatus;
var refreshTimer = null;

$(document).ready(function() {
    scanId = $('#scan-id').val();
    scanStatus = $('#scan-status').val();
    browseResults();
    startAutoRefresh();
});

function startAutoRefresh() {
    if (scanStatus === 'RUNNING' || scanStatus === 'CREATED') {
        refreshTimer = setInterval(function() {
            sf.fetchData(docroot + '/api/scanstatus?id=' + scanId, null, function(data) {
                if (data && data.status) {
                    scanStatus = data.status;
                    $('#scan-status').val(scanStatus);
                    // Update badge.
                    var badge = $('h2 .label');
                    badge.text(scanStatus);
                    badge.removeClass('label-success label-info label-warning label-danger label-default');
                    if (scanStatus === 'FINISHED') badge.addClass('label-success');
                    else if (scanStatus === 'RUNNING' || scanStatus === 'CREATED') badge.addClass('label-info');
                    else if (scanStatus === 'ABORTED') badge.addClass('label-warning');
                    else if (scanStatus === 'ERROR-FAILED') badge.addClass('label-danger');
                    else badge.addClass('label-default');

                    if (scanStatus !== 'RUNNING' && scanStatus !== 'CREATED') {
                        clearInterval(refreshTimer);
                        refreshTimer = null;
                        refreshView(); // Final refresh of results.
                    }
                }
            });
        }, 3000);
    }
}

function browseResults() {
    setActiveButton('btn-browse');
    $('#loader').show();
    sf.fetchData(docroot + '/api/scans/' + scanId + '/results', null, function(events) {
        var content = $('#scan-content');
        content.empty();

        if (!events || events.length === 0) {
            content.html('<p>No results yet.</p>');
            $('#loader').hide();
            return;
        }

        var html = '<table class="table table-striped table-condensed tablesorter" id="results-table">' +
            '<thead><tr><th>Type</th><th>Module</th><th>Data</th><th>Source</th><th>Time</th><th>FP</th></tr></thead><tbody>';

        events.forEach(function(evt) {
            html += '<tr>' +
                '<td>' + escapeHtml(evt.Type) + '</td>' +
                '<td>' + escapeHtml(evt.Module) + '</td>' +
                '<td>' + escapeHtml(truncate(evt.Data, 120)) + '</td>' +
                '<td>' + escapeHtml(evt.SourceEventHash).substring(0, 12) + '</td>' +
                '<td>' + sf.formatTimestamp(evt.Generated) + '</td>' +
                '<td>' + (evt.FalsePositive ? 'Yes' : '') + '</td>' +
                '</tr>';
        });

        html += '</tbody></table>';
        content.html(html);

        if ($.fn.tablesorter) {
            $('#results-table').tablesorter();
        }
        $('#loader').hide();
    });
}

function viewSummary() {
    setActiveButton('btn-summary');
    $('#loader').show();
    sf.fetchData(docroot + '/api/scans/' + scanId + '/summary', null, function(summary) {
        var content = $('#scan-content');
        content.empty();

        if (!summary || summary.length === 0) {
            content.html('<p>No results summary available.</p>');
            $('#loader').hide();
            return;
        }

        var html = '<table class="table table-striped table-condensed tablesorter" id="summary-table">' +
            '<thead><tr><th>Event Type</th><th>Count</th></tr></thead><tbody>';

        var total = 0;
        summary.forEach(function(s) {
            html += '<tr><td><a href="#" onclick="browseResultsFiltered(\'' + s.Type + '\'); return false;">' +
                escapeHtml(s.Type) + '</a></td><td>' + s.Count + '</td></tr>';
            total += s.Count;
        });

        html += '</tbody><tfoot><tr><th>Total</th><th>' + total + '</th></tr></tfoot></table>';
        content.html(html);

        if ($.fn.tablesorter) {
            $('#summary-table').tablesorter();
        }
        $('#loader').hide();
    });
}

function browseResultsFiltered(type) {
    setActiveButton('btn-browse');
    $('#loader').show();
    sf.fetchData(docroot + '/api/scans/' + scanId + '/results?type=' + encodeURIComponent(type), null, function(events) {
        var content = $('#scan-content');
        content.empty();

        var html = '<p><a href="#" onclick="browseResults(); return false;">&laquo; Back to all results</a> | Filtered by: <strong>' + escapeHtml(type) + '</strong></p>';
        html += '<table class="table table-striped table-condensed tablesorter" id="results-table">' +
            '<thead><tr><th>Module</th><th>Data</th><th>Source</th><th>Time</th></tr></thead><tbody>';

        if (events) {
            events.forEach(function(evt) {
                html += '<tr>' +
                    '<td>' + escapeHtml(evt.Module) + '</td>' +
                    '<td>' + escapeHtml(evt.Data) + '</td>' +
                    '<td>' + escapeHtml(evt.SourceEventHash).substring(0, 12) + '</td>' +
                    '<td>' + sf.formatTimestamp(evt.Generated) + '</td>' +
                    '</tr>';
            });
        }

        html += '</tbody></table>';
        content.html(html);
        if ($.fn.tablesorter) { $('#results-table').tablesorter(); }
        $('#loader').hide();
    });
}

function viewLog() {
    setActiveButton('btn-log');
    $('#loader').show();
    sf.fetchData(docroot + '/api/scans/' + scanId + '/log?limit=200', null, function(logs) {
        var content = $('#scan-content');
        content.empty();

        if (!logs || logs.length === 0) {
            content.html('<p>No log entries.</p>');
            $('#loader').hide();
            return;
        }

        var html = '<table class="table table-striped table-condensed" id="log-table">' +
            '<thead><tr><th>Time</th><th>Component</th><th>Type</th><th>Message</th></tr></thead><tbody>';

        logs.forEach(function(entry) {
            html += '<tr><td>' + sf.formatTimestamp(entry.Generated) + '</td>' +
                '<td>' + escapeHtml(entry.Component) + '</td>' +
                '<td>' + escapeHtml(entry.Type) + '</td>' +
                '<td>' + escapeHtml(entry.Message) + '</td></tr>';
        });

        html += '</tbody></table>';
        content.html(html);
        $('#loader').hide();
    });
}

function searchResults() {
    var query = $('#search-input').val().trim();
    if (!query) { browseResults(); return; }

    $('#loader').show();
    sf.fetchData(docroot + '/api/scans/' + scanId + '/search?value=' + encodeURIComponent(query), null, function(events) {
        var content = $('#scan-content');
        content.empty();

        var html = '<p><a href="#" onclick="browseResults(); return false;">&laquo; Back to all results</a> | Search: <strong>' + escapeHtml(query) + '</strong> (' + (events ? events.length : 0) + ' results)</p>';
        html += '<table class="table table-striped table-condensed tablesorter" id="results-table">' +
            '<thead><tr><th>Type</th><th>Module</th><th>Data</th><th>Time</th></tr></thead><tbody>';

        if (events) {
            events.forEach(function(evt) {
                html += '<tr><td>' + escapeHtml(evt.Type) + '</td>' +
                    '<td>' + escapeHtml(evt.Module) + '</td>' +
                    '<td>' + escapeHtml(evt.Data) + '</td>' +
                    '<td>' + sf.formatTimestamp(evt.Generated) + '</td></tr>';
            });
        }

        html += '</tbody></table>';
        content.html(html);
        if ($.fn.tablesorter) { $('#results-table').tablesorter(); }
        $('#loader').hide();
    });
}

function exportData(format) {
    window.location.href = docroot + '/api/scans/' + scanId + '/export?format=' + format;
}

function refreshView() {
    var active = $('.btn-toolbar .btn.active').attr('id');
    if (active === 'btn-summary') viewSummary();
    else if (active === 'btn-log') viewLog();
    else browseResults();
}

function setActiveButton(id) {
    $('.btn-toolbar .btn-group-sm .btn').removeClass('active');
    $('#' + id).addClass('active');
}

function truncate(str, len) {
    if (!str) return '';
    return str.length > len ? str.substring(0, len) + '...' : str;
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
