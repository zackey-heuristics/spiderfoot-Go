// SpiderFoot core JavaScript utilities.
// The global 'docroot' variable is set by the base template.

var sf = {};

sf.fetchData = function(url, postData, callback) {
    var opts = {
        url: url,
        dataType: 'json',
        success: function(data) {
            if (callback) callback(data);
        },
        error: function(xhr, status, error) {
            console.error('sf.fetchData error:', url, status, error);
            alertify.error('Request failed: ' + error);
        }
    };
    if (postData) {
        opts.method = 'POST';
        opts.contentType = 'application/json';
        opts.data = JSON.stringify(postData);
    }
    $.ajax(opts);
};

sf.deleteScan = function(id, callback) {
    if (!confirm('Delete this scan? This cannot be undone.')) return;
    sf.fetchData(docroot + '/api/scans/' + id + '/delete', {}, function(data) {
        if (callback) callback(data);
    });
};

sf.stopScan = function(id, callback) {
    sf.fetchData(docroot + '/api/stopscan', {id: id}, function(data) {
        if (callback) callback(data);
    });
};

sf.log = function(msg) {
    console.log('[SpiderFoot] ' + new Date().toISOString() + ' ' + msg);
};

sf.replace_sfurltag = function(data) {
    if (!data) return data;
    return data.replace(/<sfurl>(.*?)<\/sfurl>/g, '<a href="$1" target="_blank">$1</a>');
};

sf.remove_sfurltag = function(data) {
    if (!data) return data;
    return data.replace(/<\/?sfurl>/g, '');
};

sf.formatTimestamp = function(ts) {
    if (!ts || ts === 0) return '-';
    var d = new Date(ts);
    return d.toLocaleString();
};

sf.updateTooltips = function() {
    $('[data-toggle="tooltip"]').tooltip();
};
