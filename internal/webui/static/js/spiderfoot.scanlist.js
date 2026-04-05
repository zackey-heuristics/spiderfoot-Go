// SpiderFoot scan list page logic.

var currentFilter = 'all';

function scanListReload() {
    $('#loader').show();
    sf.fetchData(docroot + '/api/scans', null, function(scans) {
        renderScanTable(scans);
        $('#loader').hide();
    });
}

function renderScanTable(scans) {
    var tbody = $('#scanlist-tbody');
    tbody.empty();

    if (!scans || scans.length === 0) {
        tbody.append('<tr><td colspan="7" style="text-align:center;">No scans found. <a href="' + docroot + '/newscan">Start a new scan</a>.</td></tr>');
        return;
    }

    scans.forEach(function(s) {
        var statusClass = 'label-default';
        if (s.Status === 'FINISHED') statusClass = 'label-success';
        else if (s.Status === 'RUNNING' || s.Status === 'CREATED') statusClass = 'label-info';
        else if (s.Status === 'ABORTED' || s.Status === 'ABORT-REQUESTED') statusClass = 'label-warning';
        else if (s.Status === 'ERROR-FAILED') statusClass = 'label-danger';

        var row = '<tr data-status="' + s.Status + '">' +
            '<td><input type="checkbox" class="scan-check" value="' + s.GUID + '"></td>' +
            '<td><a href="' + docroot + '/scaninfo?id=' + s.GUID + '">' + escapeHtml(s.Name) + '</a></td>' +
            '<td>' + escapeHtml(s.SeedTarget) + '</td>' +
            '<td>' + sf.formatTimestamp(s.Started) + '</td>' +
            '<td>' + sf.formatTimestamp(s.Ended) + '</td>' +
            '<td><span class="label ' + statusClass + '">' + s.Status + '</span></td>' +
            '<td>-</td>' +
            '</tr>';
        tbody.append(row);
    });

    applyFilter();

    // Initialize tablesorter if available.
    if ($.fn.tablesorter) {
        $('#scanlist').trigger('update');
    }
}

function applyFilter() {
    $('#scanlist-tbody tr').each(function() {
        var status = $(this).data('status');
        var show = false;
        switch (currentFilter) {
            case 'all': show = true; break;
            case 'running': show = (status === 'RUNNING' || status === 'CREATED' || status === 'ABORT-REQUESTED'); break;
            case 'finished': show = (status === 'FINISHED'); break;
            case 'failed': show = (status === 'ABORTED' || status === 'ERROR-FAILED'); break;
        }
        $(this).toggle(show);
    });
}

function filterScans(filter, btn) {
    currentFilter = filter;
    $('.btn-group-sm .btn').removeClass('active');
    $(btn).addClass('active');
    applyFilter();
}

function toggleCheckAll(el) {
    $('.scan-check:visible').prop('checked', el.checked);
}

function getSelected() {
    var ids = [];
    $('.scan-check:checked').each(function() {
        ids.push($(this).val());
    });
    return ids;
}

function stopSelected() {
    var ids = getSelected();
    if (ids.length === 0) { alertify.warning('No scans selected.'); return; }
    ids.forEach(function(id) {
        sf.stopScan(id, function() { scanListReload(); });
    });
}

function deleteSelected() {
    var ids = getSelected();
    if (ids.length === 0) { alertify.warning('No scans selected.'); return; }
    if (!confirm('Delete ' + ids.length + ' scan(s)? This cannot be undone.')) return;
    var remaining = ids.length;
    ids.forEach(function(id) {
        sf.fetchData(docroot + '/api/scans/' + id + '/delete', {}, function() {
            remaining--;
            if (remaining <= 0) scanListReload();
        });
    });
}

function rerunSelected() {
    var ids = getSelected();
    if (ids.length === 0) { alertify.warning('No scans selected.'); return; }
    alertify.warning('Re-run not yet implemented.');
}

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// Load scan list on page ready.
$(document).ready(function() {
    scanListReload();
    if ($.fn.tablesorter) {
        $('#scanlist').tablesorter({
            headers: { 0: { sorter: false } }
        });
    }
});
