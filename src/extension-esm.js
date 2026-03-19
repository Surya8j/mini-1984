/**
 * mini-1984 — GNOME Shell Topbar Extension
 *
 * Endpoint monitoring:
 *   1. Screenshot/screencast detection on sensitive sites
 *   2. Personal email login detection
 *
 * Config: /etc/mini-1984/config.json (admin) or ~/.config/mini-1984/config.json (local)
 * Logs: JSON events for SIEM ingestion
 *
 * Target: GNOME 45+ (ESM format)
 */

import GLib from 'gi://GLib';
import GObject from 'gi://GObject';
import Gio from 'gi://Gio';
import St from 'gi://St';
import Clutter from 'gi://Clutter';

import * as Main from 'resource:///org/gnome/shell/ui/main.js';
import * as PanelMenu from 'resource:///org/gnome/shell/ui/panelMenu.js';
import { Extension } from 'resource:///org/gnome/shell/extensions/extension.js';

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

const SCREENSHOT_WM_CLASSES = [
    'flameshot', 'gnome-screenshot', 'screenshot', 'spectacle',
    'ksnip', 'shutter', 'peek', 'kazam', 'obs',
    'simplescreenrecorder', 'scrot', 'maim',
];

const BROWSER_WM_CLASSES = [
    'firefox', 'google-chrome', 'chromium', 'brave', 'vivaldi',
    'opera', 'microsoft-edge', 'zen', 'librewolf', 'waterfox', 'thorium',
];

const CONFIG_PATHS = [
    '/etc/mini-1984/config.json',
    GLib.build_filenamev([GLib.get_home_dir(), '.config', 'mini-1984', 'config.json']),
];

const DEFAULT_CONFIG = {
    show_icon: true,
    warning_duration: 5,
    screenshot: {
        enabled: true,
        sensitive_patterns: [],
        ignore_patterns: ['Google Search', '- Google -', 'google.com/search'],
    },
    email: {
        enabled: true,
        personal_patterns: ['@gmail.com', '@yahoo.com', '@outlook.com', '@hotmail.com',
                           '@protonmail.com', '@icloud.com', '@aol.com', '@yandex.com', '@mail.com'],
        work_patterns: [],
    },
    log_path: '',
};

/* ------------------------------------------------------------------ */
/*  Indicator                                                          */
/* ------------------------------------------------------------------ */

const Mini1984Indicator = GObject.registerClass(
class Mini1984Indicator extends PanelMenu.Button {

    _init() {
        super._init(0.0, 'mini-1984');

        this._config = {};
        this._dismissTimeoutId = null;
        this._windowSignalId = null;
        this._emailPollId = null;
        this._printPollId = null;
        this._dbusWatchId = null;
        this._screenshotMonitors = [];
        this._isWarning = false;
        this._logPath = null;
        this._lastTriggerTime = 0;
        this._seenEmailTitles = new Set();
        this._knownPrintPids = new Set();

        this._loadConfig();
        this._resolveLogPath();

        this._box = new St.BoxLayout({
            style_class: 'panel-status-menu-box',
        });

        this._icon = new St.Label({
            text: ':)',
            y_align: Clutter.ActorAlign.CENTER,
            style: 'font-weight: bold; font-size: 14px; color: #aaaaaa;',
        });

        this._box.add_child(this._icon);
        this.add_child(this._box);

        if (!this._config.show_icon) {
            this.hide();
        }

        if (this._config.screenshot.enabled) {
            this._startWindowMonitor();
            this._startScreenshotDBusMonitor();
            this._startPrintMonitor();
        }

        if (this._config.email.enabled) {
            this._startEmailMonitor();
        }
    }

    _loadConfig() {
        this._config = JSON.parse(JSON.stringify(DEFAULT_CONFIG));

        for (let i = 0; i < CONFIG_PATHS.length; i++) {
            try {
                const file = Gio.File.new_for_path(CONFIG_PATHS[i]);
                if (!file.query_exists(null)) continue;

                const [ok, contents] = file.load_contents(null);
                if (!ok) continue;

                const userConfig = JSON.parse(new TextDecoder().decode(contents));

                if (userConfig.show_icon !== undefined)
                    this._config.show_icon = userConfig.show_icon;
                if (userConfig.warning_duration !== undefined)
                    this._config.warning_duration = userConfig.warning_duration;
                if (userConfig.log_path !== undefined)
                    this._config.log_path = userConfig.log_path;

                if (userConfig.screenshot) {
                    if (userConfig.screenshot.enabled !== undefined)
                        this._config.screenshot.enabled = userConfig.screenshot.enabled;
                    if (userConfig.screenshot.sensitive_patterns)
                        this._config.screenshot.sensitive_patterns = userConfig.screenshot.sensitive_patterns;
                    if (userConfig.screenshot.ignore_patterns)
                        this._config.screenshot.ignore_patterns = userConfig.screenshot.ignore_patterns;
                }

                if (userConfig.email) {
                    if (userConfig.email.enabled !== undefined)
                        this._config.email.enabled = userConfig.email.enabled;
                    if (userConfig.email.personal_patterns)
                        this._config.email.personal_patterns = userConfig.email.personal_patterns;
                    if (userConfig.email.work_patterns)
                        this._config.email.work_patterns = userConfig.email.work_patterns;
                }

                break;
            } catch (_e) { }
        }
    }

    _resolveLogPath() {
        if (this._config.log_path && this._config.log_path.length > 0) {
            this._logPath = this._config.log_path;
        } else {
            const dataDir = GLib.build_filenamev([
                GLib.get_home_dir(), '.local', 'share', 'mini-1984',
            ]);
            GLib.mkdir_with_parents(dataDir, 0o755);
            this._logPath = GLib.build_filenamev([dataDir, 'events.log']);
        }
    }

    _startWindowMonitor() {
        const display = global.display;

        this._windowSignalId = display.connect('window-created', (display, metaWindow) => {
            if (!metaWindow) return;

            const wmClass = (metaWindow.get_wm_class() || '').toLowerCase();
            const title = (metaWindow.get_title() || '').toLowerCase();

            let detectedTool = null;
            for (let i = 0; i < SCREENSHOT_WM_CLASSES.length; i++) {
                if (wmClass.indexOf(SCREENSHOT_WM_CLASSES[i]) !== -1 ||
                    title.indexOf(SCREENSHOT_WM_CLASSES[i]) !== -1) {
                    detectedTool = SCREENSHOT_WM_CLASSES[i];
                    break;
                }
            }

            if (detectedTool) {
                this._onScreenshotDetected('window_monitor', detectedTool);
            }
        });
    }

    _startScreenshotDBusMonitor() {
        try {
            const bus = Gio.DBus.session;
            const self = this;

            this._dbusWatchId = bus.signal_subscribe(
                null, 'org.gnome.Shell.Screenshot', null,
                '/org/gnome/Shell/Screenshot', null,
                Gio.DBusSignalFlags.NONE,
                function() {
                    self._onScreenshotDetected('dbus_screenshot', 'gnome-shell-screenshot');
                }
            );

            const home = GLib.get_home_dir();
            const watchDirsSet = {};

            try {
                const [okP, outP] = GLib.spawn_command_line_sync('xdg-user-dir PICTURES');
                if (okP) { const p = new TextDecoder().decode(outP).trim(); if (p) watchDirsSet[p] = true; }
            } catch (_e) { }

            try {
                const [okV, outV] = GLib.spawn_command_line_sync('xdg-user-dir VIDEOS');
                if (okV) {
                    const v = new TextDecoder().decode(outV).trim();
                    if (v) { watchDirsSet[v] = true; watchDirsSet[v + '/Screencasts'] = true; }
                }
            } catch (_e) { }

            try {
                const flameshotIni = GLib.build_filenamev([home, '.config', 'flameshot', 'flameshot.ini']);
                const iniFile = Gio.File.new_for_path(flameshotIni);
                if (iniFile.query_exists(null)) {
                    const [ok, contents] = iniFile.load_contents(null);
                    if (ok) {
                        const match = new TextDecoder().decode(contents).match(/savePath=(.+)/);
                        if (match && match[1]) watchDirsSet[match[1].trim()] = true;
                    }
                }
            } catch (_e) { }

            watchDirsSet[GLib.get_tmp_dir()] = true;
            watchDirsSet[GLib.build_filenamev([home, 'Pictures'])] = true;
            watchDirsSet[GLib.build_filenamev([home, 'Pictures', 'Screenshots'])] = true;
            watchDirsSet[GLib.build_filenamev([home, 'Videos'])] = true;
            watchDirsSet[GLib.build_filenamev([home, 'Videos', 'Screencasts'])] = true;

            const watchDirs = Object.keys(watchDirsSet);

            for (let i = 0; i < watchDirs.length; i++) {
                try {
                    const dir = Gio.File.new_for_path(watchDirs[i]);
                    if (!dir.query_exists(null)) continue;

                    const monitor = dir.monitor_directory(Gio.FileMonitorFlags.NONE, null);
                    monitor.connect('changed', (monitor, file, otherFile, eventType) => {
                        if (eventType !== Gio.FileMonitorEvent.CREATED) return;
                        const name = file.get_basename().toLowerCase();
                        if (name.indexOf('screenshot') !== -1 || name.match(/\.(png|jpg|jpeg|bmp)$/))
                            self._onScreenshotDetected('file_monitor', 'screenshot-file');
                        if (name.indexOf('screencast') !== -1 || name.match(/\.(webm|mp4|mkv)$/))
                            self._onScreenshotDetected('file_monitor', 'screencast-file');
                    });
                    this._screenshotMonitors.push(monitor);
                } catch (_e) { }
            }
        } catch (_e) { }
    }

    _startPrintMonitor() {
        this._printPollId = GLib.timeout_add(
            GLib.PRIORITY_DEFAULT,
            500,
            () => {
                this._checkForPrintProcess();
                return GLib.SOURCE_CONTINUE;
            }
        );
    }

    _checkForPrintProcess() {
        try {
            const [ok, stdout, stderr, exitCode] = GLib.spawn_command_line_sync(
                'pgrep -f printing.mojom'
            );

            if (!ok || exitCode !== 0) return;

            const output = new TextDecoder().decode(stdout).trim();
            if (output.length === 0) return;

            const pids = output.split('\n');
            for (let i = 0; i < pids.length; i++) {
                const pid = parseInt(pids[i].trim());
                if (isNaN(pid) || this._knownPrintPids.has(pid)) continue;

                this._knownPrintPids.add(pid);
                this._onScreenshotDetected('print_monitor', 'browser-print');
            }
        } catch (_e) { }

        const toDelete = [];
        this._knownPrintPids.forEach(pid => {
            try {
                const statFile = Gio.File.new_for_path('/proc/' + pid + '/stat');
                if (!statFile.query_exists(null)) {
                    toDelete.push(pid);
                }
            } catch (_e) {
                toDelete.push(pid);
            }
        });
        for (let i = 0; i < toDelete.length; i++) {
            this._knownPrintPids.delete(toDelete[i]);
        }
    }

    _onScreenshotDetected(source, tool) {
        const now = GLib.get_monotonic_time();
        if (this._lastTriggerTime && (now - this._lastTriggerTime) < 3000000) return;
        this._lastTriggerTime = now;

        const sensitiveWindows = this._findSensitiveBrowserWindows();
        if (sensitiveWindows.length === 0) return;

        this._showWarning();
        this._logEvent({
            timestamp: new Date().toISOString(),
            event_type: 'screenshot_on_sensitive_site',
            hostname: GLib.get_host_name(),
            user: GLib.get_user_name(),
            detection_source: source,
            detection_tool: tool,
            sensitive_windows: sensitiveWindows,
        });
    }

    _findSensitiveBrowserWindows() {
        const matches = [];
        const actors = global.get_window_actors();
        const patterns = this._config.screenshot.sensitive_patterns.map(p => p.toLowerCase());
        const ignorePatterns = this._config.screenshot.ignore_patterns.map(p => p.toLowerCase());

        if (patterns.length === 0) return matches;
        const activeWorkspace = global.workspace_manager.get_active_workspace();

        for (let i = 0; i < actors.length; i++) {
            const metaWindow = actors[i].get_meta_window();
            if (!metaWindow) continue;
            if (!metaWindow.is_on_all_workspaces() && metaWindow.get_workspace() !== activeWorkspace) continue;
            if (metaWindow.minimized) continue;

            const wmClass = (metaWindow.get_wm_class() || '').toLowerCase();
            let isBrowser = false;
            for (let b = 0; b < BROWSER_WM_CLASSES.length; b++) {
                if (wmClass.indexOf(BROWSER_WM_CLASSES[b]) !== -1) { isBrowser = true; break; }
            }
            if (!isBrowser) continue;

            const title = (metaWindow.get_title() || '').toLowerCase();
            if (!title) continue;

            let ignored = false;
            for (let g = 0; g < ignorePatterns.length; g++) {
                if (title.indexOf(ignorePatterns[g]) !== -1) { ignored = true; break; }
            }
            if (ignored) continue;

            for (let p = 0; p < patterns.length; p++) {
                if (title.indexOf(patterns[p]) !== -1) {
                    matches.push({ title: metaWindow.get_title(), browser: metaWindow.get_wm_class(), match_type: 'pattern', match_value: patterns[p] });
                    break;
                }
            }
        }
        return matches;
    }

    _startEmailMonitor() {
        this._emailPollId = GLib.timeout_add_seconds(GLib.PRIORITY_DEFAULT, 5, () => {
            this._checkForPersonalEmail();
            return GLib.SOURCE_CONTINUE;
        });
    }

    _checkForPersonalEmail() {
        const actors = global.get_window_actors();
        const personalPatterns = this._config.email.personal_patterns.map(p => p.toLowerCase());
        const workPatterns = this._config.email.work_patterns.map(p => p.toLowerCase());

        if (personalPatterns.length === 0) return;
        const activeWorkspace = global.workspace_manager.get_active_workspace();

        for (let i = 0; i < actors.length; i++) {
            const metaWindow = actors[i].get_meta_window();
            if (!metaWindow) continue;
            if (!metaWindow.is_on_all_workspaces() && metaWindow.get_workspace() !== activeWorkspace) continue;
            if (metaWindow.minimized) continue;

            const wmClass = (metaWindow.get_wm_class() || '').toLowerCase();
            let isBrowser = false;
            for (let b = 0; b < BROWSER_WM_CLASSES.length; b++) {
                if (wmClass.indexOf(BROWSER_WM_CLASSES[b]) !== -1) { isBrowser = true; break; }
            }
            if (!isBrowser) continue;

            const title = (metaWindow.get_title() || '').toLowerCase();
            if (!title) continue;

            let isWork = false;
            for (let w = 0; w < workPatterns.length; w++) {
                if (title.indexOf(workPatterns[w]) !== -1) { isWork = true; break; }
            }
            if (isWork) continue;

            for (let p = 0; p < personalPatterns.length; p++) {
                if (title.indexOf(personalPatterns[p]) !== -1) {
                    const windowId = metaWindow.get_stable_sequence();
                    const dedupeKey = windowId + ':' + title;
                    if (this._seenEmailTitles.has(dedupeKey)) break;
                    this._seenEmailTitles.add(dedupeKey);

                    this._showWarning();
                    this._logEvent({
                        timestamp: new Date().toISOString(),
                        event_type: 'personal_email_detected',
                        hostname: GLib.get_host_name(),
                        user: GLib.get_user_name(),
                        detection_source: 'email_monitor',
                        window_title: metaWindow.get_title(),
                        browser: metaWindow.get_wm_class(),
                        matched_pattern: personalPatterns[p],
                    });
                    break;
                }
            }
        }
    }

    _showWarning() {
        if (this._dismissTimeoutId) {
            GLib.source_remove(this._dismissTimeoutId);
            this._dismissTimeoutId = null;
        }

        this._isWarning = true;

        if (this._config.show_icon) {
            this._icon.set_text(':(');
            this._icon.set_style('font-weight: bold; font-size: 14px; color: #ff5555;');
        }

        this._dismissTimeoutId = GLib.timeout_add(
            GLib.PRIORITY_DEFAULT,
            this._config.warning_duration * 1000,
            () => { this._hideWarning(); this._dismissTimeoutId = null; return GLib.SOURCE_REMOVE; }
        );
    }

    _hideWarning() {
        if (this._config.show_icon) {
            this._icon.set_text(':)');
            this._icon.set_style('font-weight: bold; font-size: 14px; color: #aaaaaa;');
        }
        this._isWarning = false;
    }

    _logEvent(event) {
        try {
            const line = JSON.stringify(event) + '\n';
            const file = Gio.File.new_for_path(this._logPath);
            const stream = file.append_to(Gio.FileCreateFlags.NONE, null);
            const bytes = new GLib.Bytes(line);
            stream.write_bytes(bytes, null);
            stream.close(null);
        } catch (e) {
            console.error('[mini-1984] Failed to write log: ' + e.message);
        }
    }

    destroy() {
        if (this._windowSignalId) { global.display.disconnect(this._windowSignalId); this._windowSignalId = null; }
        if (this._dbusWatchId) { try { Gio.DBus.session.signal_unsubscribe(this._dbusWatchId); } catch (_e) { } this._dbusWatchId = null; }
        if (this._emailPollId) { GLib.source_remove(this._emailPollId); this._emailPollId = null; }
        if (this._printPollId) { GLib.source_remove(this._printPollId); this._printPollId = null; }
        if (this._dismissTimeoutId) { GLib.source_remove(this._dismissTimeoutId); this._dismissTimeoutId = null; }
        if (this._screenshotMonitors) { for (let i = 0; i < this._screenshotMonitors.length; i++) { try { this._screenshotMonitors[i].cancel(); } catch (_e) { } } this._screenshotMonitors = []; }
        this._seenEmailTitles.clear();
        this._knownPrintPids.clear();
        super.destroy();
    }
});

/* ------------------------------------------------------------------ */
/*  Extension entry point (GNOME 45+ ESM)                              */
/* ------------------------------------------------------------------ */

export default class Mini1984Extension extends Extension {
    enable() {
        this._indicator = new Mini1984Indicator();
        Main.panel.addToStatusArea(this.metadata.uuid, this._indicator);
    }

    disable() {
        if (this._indicator) { this._indicator.destroy(); this._indicator = null; }
    }
}
