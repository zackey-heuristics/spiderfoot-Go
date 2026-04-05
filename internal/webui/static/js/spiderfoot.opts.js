// SpiderFoot settings page logic.

var currentSettingsTab = 'global';

$(document).ready(function() {
    loadSettings();
    loadModuleTabs();
});

function loadSettings() {
    sf.fetchData(docroot + '/api/config', null, function(config) {
        renderSettings('global', config);
    });
}

function loadModuleTabs() {
    sf.fetchData(docroot + '/api/modules', null, function(modules) {
        var tabs = $('#settings-tabs');
        $('#module-tabs-loading').hide();
        if (!modules) return;
        modules.forEach(function(mod) {
            tabs.append('<li><a href="#" onclick="switchSettingsTab(\'' +
                mod.Name + '\', this); return false;">' + escapeHtml(mod.Name) + '</a></li>');
        });
    });
}

function switchSettingsTab(tab, el) {
    currentSettingsTab = tab;
    $('#settings-tabs li').removeClass('active');
    $(el).parent().addClass('active');

    if (tab === 'global') {
        loadSettings();
    } else {
        // Show module info.
        var content = $('#settings-content');
        content.html('<p>Module-specific settings for <strong>' + escapeHtml(tab) + '</strong> will be available when module configuration is implemented.</p>');
    }
}

function renderSettings(tab, config) {
    var content = $('#settings-content');
    content.empty();

    if (!config || Object.keys(config).length === 0) {
        content.html('<p>No settings configured.</p>');
        return;
    }

    var html = '<table class="table table-striped"><thead><tr><th>Key</th><th>Value</th></tr></thead><tbody>';
    var keys = Object.keys(config).sort();
    keys.forEach(function(key) {
        html += '<tr><td>' + escapeHtml(key) + '</td>' +
            '<td><input type="text" class="form-control input-sm config-input" data-key="' +
            escapeHtml(key) + '" value="' + escapeHtml(config[key]) + '"></td></tr>';
    });
    html += '</tbody></table>';
    content.html(html);
}

function saveSettings() {
    var config = {};
    $('.config-input').each(function() {
        config[$(this).data('key')] = $(this).val();
    });

    sf.fetchData(docroot + '/api/config', config, function(data) {
        if (data && data.status === 'ok') {
            alertify.success('Settings saved.');
        } else {
            alertify.error('Failed to save settings.');
        }
    });
}

function exportSettings() {
    sf.fetchData(docroot + '/api/config', null, function(config) {
        var blob = new Blob([JSON.stringify(config, null, 2)], {type: 'application/json'});
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url; a.download = 'spiderfoot-config.json';
        a.click();
        URL.revokeObjectURL(url);
    });
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
