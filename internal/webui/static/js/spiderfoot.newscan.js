// SpiderFoot new scan page logic.

$(document).ready(function() {
    loadModules();
    loadEventTypes();

    $('#startscan-form').submit(function(e) {
        e.preventDefault();
        startScan();
    });
});

function loadModules() {
    sf.fetchData(docroot + '/api/modules', null, function(modules) {
        var container = $('#modulelist');
        container.empty();
        if (!modules || modules.length === 0) {
            container.html('<p>No modules available.</p>');
            return;
        }
        modules.forEach(function(mod) {
            var label = '<div class="checkbox"><label>' +
                '<input type="checkbox" class="mod-check" value="' + mod.Name + '" checked> ' +
                '<strong>' + escapeHtml(mod.Name) + '</strong> — ' + escapeHtml(mod.Summary) +
                '</label></div>';
            container.append(label);
        });
    });
}

function loadEventTypes() {
    sf.fetchData(docroot + '/api/eventtypes', null, function(types) {
        var container = $('#typelist');
        container.empty();
        if (!types) return;
        for (var key in types) {
            if (!types.hasOwnProperty(key)) continue;
            var info = types[key];
            var label = '<div class="checkbox"><label>' +
                '<input type="checkbox" class="type-check" value="' + key + '"> ' +
                key + ' — ' + escapeHtml(info.Description) +
                '</label></div>';
            container.append(label);
        }
    });
}

function startScan() {
    var name = $('#scanname').val().trim();
    var target = $('#scantarget').val().trim();

    if (!target) {
        alertify.error('Please enter a scan target.');
        return;
    }
    if (!name) {
        name = target;
    }

    // Determine module selection mode.
    var activeTab = $('#moduletabs li.active a').attr('href');
    var body = { scanname: name, scantarget: target };

    if (activeTab === '#byusecase') {
        body.usecase = $('input[name="usecase"]:checked').val() || 'all';
    } else if (activeTab === '#bytype') {
        var types = [];
        $('.type-check:checked').each(function() { types.push($(this).val()); });
        body.typelist = types.join(',');
    } else {
        var mods = [];
        $('.mod-check:checked').each(function() { mods.push($(this).val()); });
        body.modulelist = mods.join(',');
    }

    sf.fetchData(docroot + '/api/startscan', body, function(data) {
        if (data && data.scanId) {
            window.location.href = docroot + '/scaninfo?id=' + data.scanId;
        } else {
            alertify.error('Failed to start scan.');
        }
    });
}

function selectAllModules() {
    $('.mod-check').prop('checked', true);
}

function deselectAllModules() {
    $('.mod-check').prop('checked', false);
}

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
