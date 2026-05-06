import Cocoa
import UserNotifications

final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate, NSMenuItemValidation {
    private let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    private let menu = NSMenu()
    private let languageKey = "ZapretMenuLanguage"
    private let startTimeKey = "ZapretLastStartTime"
    private let stopTimeKey = "ZapretLastStopTime"
    private var refreshTimer: Timer?
    private var restartingUntil: Date?
    private var lockFileDescriptor: Int32 = -1

    private enum Language: String {
        case auto
        case ru
        case en
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
        guard acquireSingleInstanceLock() else {
            NSApp.terminate(nil)
            return
        }
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }

        if let button = statusItem.button {
            button.toolTip = "Zapret"
        }

        rebuildMenu()
        refreshTimer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            self?.updateStatusIcon()
        }
    }

    private func rebuildMenu() {
        menu.removeAllItems()
        menu.delegate = self
        menu.autoenablesItems = true
        updateStatusIcon()
        let running = isZapretRunning()
        let connectionAvailable = isInternetReachable()

        let header = NSMenuItem(title: currentStatusTitle(), action: nil, keyEquivalent: "")
        header.isEnabled = false
        menu.addItem(header)
        menu.addItem(.separator())

        let startItem = item(text("start"), #selector(startZapret))
        startItem.isEnabled = !running
        menu.addItem(startItem)

        let stopItem = item(text("stop"), #selector(stopZapret))
        stopItem.isEnabled = running
        menu.addItem(stopItem)

        let restartItem = item(text("restart"), #selector(restartZapret))
        restartItem.isEnabled = running && connectionAvailable
        menu.addItem(restartItem)
        menu.addItem(.separator())
        menu.addItem(item(text("updateHostlist"), #selector(updateHostlist)))
        menu.addItem(item(text("checkConnection"), #selector(checkConnection)))
        menu.addItem(item(text("showStatus"), #selector(showStatus)))
        menu.addItem(item(text("about"), #selector(showAbout)))
        menu.addItem(item(languageMenuTitle(), #selector(toggleLanguage)))
        menu.addItem(.separator())
        menu.addItem(item(text("quit"), #selector(quit)))

        statusItem.menu = menu
    }

    func menuWillOpen(_ menu: NSMenu) {
        rebuildMenu()
    }

    func validateMenuItem(_ menuItem: NSMenuItem) -> Bool {
        switch menuItem.action {
        case #selector(startZapret):
            return !isZapretRunning()
        case #selector(stopZapret):
            return isZapretRunning()
        case #selector(restartZapret):
            return isZapretRunning() && isInternetReachable()
        default:
            return true
        }
    }

    private func updateStatusIcon() {
        if let button = statusItem.button {
            if let until = restartingUntil, Date() < until {
                button.title = "🔀"
            } else {
                restartingUntil = nil
                button.title = isZapretRunning() ? "📳" : "📴"
            }
            button.image = nil
            button.toolTip = currentStatusTitle()
        }
    }

    private func statusImage(color: NSColor) -> NSImage {
        let size = NSSize(width: 18, height: 18)
        let image = NSImage(size: size)
        image.lockFocus()

        color.setFill()
        NSBezierPath(ovalIn: NSRect(x: 1, y: 1, width: 16, height: 16)).fill()

        NSColor.white.setFill()
        drawHand(in: NSRect(x: 3.6, y: 3.2, width: 10.8, height: 12.4))

        image.unlockFocus()
        image.isTemplate = false
        return image
    }

    private func drawHand(in rect: NSRect) {
        let palm = NSBezierPath(roundedRect: NSRect(x: rect.minX + 2.8, y: rect.minY, width: 5.4, height: 6.6), xRadius: 2.2, yRadius: 2.2)
        palm.fill()

        let fingerWidth: CGFloat = 1.8
        let gap: CGFloat = 0.45
        let baseX = rect.minX + 1.2
        let baseY = rect.minY + 5.1
        let heights: [CGFloat] = [5.8, 7.2, 6.6, 5.2]

        for index in 0..<4 {
            let x = baseX + CGFloat(index) * (fingerWidth + gap)
            let finger = NSBezierPath(roundedRect: NSRect(x: x, y: baseY, width: fingerWidth, height: heights[index]), xRadius: 0.9, yRadius: 0.9)
            finger.fill()
        }

        let thumb = NSBezierPath()
        thumb.move(to: NSPoint(x: rect.minX + 2.8, y: rect.minY + 4.3))
        thumb.line(to: NSPoint(x: rect.minX + 0.1, y: rect.minY + 5.6))
        thumb.line(to: NSPoint(x: rect.minX + 0.9, y: rect.minY + 7.3))
        thumb.line(to: NSPoint(x: rect.minX + 3.7, y: rect.minY + 5.7))
        thumb.close()
        thumb.fill()
    }

    private func item(_ title: String, _ action: Selector) -> NSMenuItem {
        let menuItem = NSMenuItem(title: title, action: action, keyEquivalent: "")
        menuItem.target = self
        return menuItem
    }

    private func currentStatusTitle() -> String {
        if let until = restartingUntil, Date() < until {
            return text("statusRestarting")
        }
        return isZapretRunning() ? text("statusRunning") : text("statusStopped")
    }

    private func isZapretRunning() -> Bool {
        let result = runShell("/usr/bin/pgrep -x tpws >/dev/null && echo yes || echo no")
        return result.trimmingCharacters(in: .whitespacesAndNewlines) == "yes"
    }

    private func isInternetReachable() -> Bool {
        let output = runShell("""
        if /sbin/ping -q -c 1 -W 1000 1.1.1.1 >/dev/null 2>&1; then
          echo yes
        elif /usr/bin/curl -Is --connect-timeout 2 --max-time 3 https://www.apple.com >/dev/null 2>&1; then
          echo yes
        else
          echo no
        fi
        """)
        return output.trimmingCharacters(in: .whitespacesAndNewlines) == "yes"
    }

    @objc private func startZapret() {
        let result = runSudo("/opt/zapret/zapret-menu-helper start")
        if result.success {
            UserDefaults.standard.set(Date().timeIntervalSince1970, forKey: startTimeKey)
            showNotification(text("started"))
        } else {
            showCommandError(result.output)
        }
        rebuildMenu()
    }

    @objc private func stopZapret() {
        let result = runSudo("/opt/zapret/zapret-menu-helper stop")
        if result.success {
            UserDefaults.standard.set(Date().timeIntervalSince1970, forKey: stopTimeKey)
            showNotification(text("stopped"))
        } else {
            showCommandError(result.output)
        }
        rebuildMenu()
    }

    @objc private func restartZapret() {
        guard isZapretRunning() else {
            showDialog(text("restartUnavailable"), title: "Zapret")
            rebuildMenu()
            return
        }
        guard isInternetReachable() else {
            showDialog(text("restartNoInternet"), title: "Zapret")
            rebuildMenu()
            return
        }

        restartingUntil = Date().addingTimeInterval(3)
        updateStatusIcon()
        let result = runSudo("/opt/zapret/zapret-menu-helper restart")
        restartingUntil = Date().addingTimeInterval(3)
        if result.success {
            UserDefaults.standard.set(Date().timeIntervalSince1970, forKey: startTimeKey)
            showNotification(text("restarted"))
        } else {
            showCommandError(result.output)
        }
        rebuildMenu()
    }

    @objc private func updateHostlist() {
        let before = hostlistLineCount()
        let result = runSudo("/opt/zapret/zapret-menu-helper update")
        let after = hostlistLineCount()
        let updatedAt = hostlistModifiedTime()
        let status = result.success ? text("hostlistUpdated") : text("hostlistUpdateFailed")
        let message = """
        \(status)

        \(text("before")) \(before)
        \(text("after")) \(after)
        \(text("lastListUpdate")) \(updatedAt)

        \(text("commandOutput"))
        \(result.output.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? text("noOutput") : result.output)
        """
        showDialog(message, title: "Zapret")
        rebuildMenu()
    }

    @objc private func checkConnection() {
        if isInternetReachable() {
            showDialog(text("internetOk"), title: "Zapret")
        } else {
            showNoInternetDialog()
        }

        rebuildMenu()
    }

    @objc private func showStatus() {
        showDialog(statusReport(), title: "Zapret")
        rebuildMenu()
    }

    @objc private func showAbout() {
        showDialog(aboutText(), title: "Zapret")
        rebuildMenu()
    }

    @objc private func toggleLanguage() {
        let newLanguage: Language = effectiveLanguage() == .ru ? .en : .ru
        UserDefaults.standard.set(newLanguage.rawValue, forKey: languageKey)
        rebuildMenu()
        showNotification(text("languageChanged"))
    }

    @objc private func quit() {
        _ = runSudo("/opt/zapret/zapret-menu-helper stop")
        UserDefaults.standard.set(Date().timeIntervalSince1970, forKey: stopTimeKey)

        let deadline = Date().addingTimeInterval(5)
        while isZapretRunning() && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.25)
        }

        NSApp.terminate(nil)
    }

    private func runAdmin(_ command: String, success: String) {
        let output = runShell("/usr/bin/sudo -n \(command) 2>&1")
        if !output.contains("a password is required") && !output.contains("not in the sudoers") {
            showNotification(success)
        } else {
            showDialog(text("passwordlessSetupMissing"), title: text("errorTitle"))
        }

        rebuildMenu()
    }

    private func showNoInternetDialog() {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = text("internetFailTitle")
        alert.informativeText = text("internetFailMessage")
        if isZapretRunning() {
            alert.addButton(withTitle: text("stop"))
        }
        alert.addButton(withTitle: text("close"))

        let response = alert.runModal()
        if response == .alertFirstButtonReturn, isZapretRunning() {
            stopZapret()
        }
    }

    private func runSudo(_ command: String) -> (success: Bool, output: String) {
        let output = runShell("/usr/bin/sudo -n \(command) 2>&1; echo __EXIT_CODE__:$?")
        let marker = "__EXIT_CODE__:"
        guard let range = output.range(of: marker, options: .backwards) else {
            return (false, output)
        }
        let codeText = output[range.upperBound...].trimmingCharacters(in: .whitespacesAndNewlines)
        let commandOutput = String(output[..<range.lowerBound])
        return (codeText == "0", commandOutput)
    }

    private func showCommandError(_ output: String) {
        if output.contains("a password is required") || output.contains("not in the sudoers") {
            showDialog(text("passwordlessSetupMissing"), title: text("errorTitle"))
        } else {
            showDialog(output.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? text("commandFailed") : output, title: text("errorTitle"))
        }
    }

    private func runShell(_ command: String) -> String {
        let process = Process()
        let pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: "/bin/sh")
        process.arguments = ["-c", command]
        process.standardOutput = pipe
        process.standardError = pipe

        do {
            try process.run()
            process.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            return String(data: data, encoding: .utf8) ?? ""
        } catch {
            return error.localizedDescription
        }
    }

    private func terminateOtherInstances() {
        // Kept for compatibility with existing installs; lock file is authoritative.
    }

    private func acquireSingleInstanceLock() -> Bool {
        let supportDirectory = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/Zapret Menu", isDirectory: true)
        try? FileManager.default.createDirectory(at: supportDirectory, withIntermediateDirectories: true)
        let lockPath = supportDirectory.appendingPathComponent("ZapretMenu.lock").path

        lockFileDescriptor = open(lockPath, O_CREAT | O_RDWR, 0o600)
        guard lockFileDescriptor >= 0 else {
            return false
        }

        if flock(lockFileDescriptor, LOCK_EX | LOCK_NB) == 0 {
            ftruncate(lockFileDescriptor, 0)
            let pid = "\(getpid())\n"
            _ = pid.withCString { write(lockFileDescriptor, $0, strlen($0)) }
            return true
        }

        close(lockFileDescriptor)
        lockFileDescriptor = -1
        return false
    }

    private func hostlistLineCount() -> String {
        runShell("/usr/bin/wc -l /opt/zapret/ipset/zapret-hosts.txt 2>/dev/null | /usr/bin/awk '{print $1}'").trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func userHostlistLineCount() -> String {
        runShell("/usr/bin/wc -l /opt/zapret/ipset/zapret-hosts-user.txt 2>/dev/null | /usr/bin/awk '{print $1}'").trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func hostlistModifiedTime() -> String {
        let output = runShell("/usr/bin/stat -f '%Sm' -t '%Y-%m-%d %H:%M:%S' /opt/zapret/ipset/zapret-hosts.txt 2>/dev/null")
        return output.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? text("unknown") : output.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func hostlistModifiedDate() -> String {
        let output = runShell("/usr/bin/stat -f '%Sm' -t '%Y-%m-%d' /opt/zapret/ipset/zapret-hosts.txt 2>/dev/null")
        return output.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? text("unknown") : output.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func appModifiedDate() -> String {
        guard let executablePath = Bundle.main.executablePath else {
            return text("unknown")
        }
        let output = runShell("/usr/bin/stat -f '%Sm' -t '%Y-%m-%d' \(shellEscape(executablePath)) 2>/dev/null")
        return output.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? text("unknown") : output.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func zapretStartedAt() -> String {
        let output = runShell("""
        pid=$(/usr/bin/pgrep -x tpws | /usr/bin/head -n 1)
        if [ -n "$pid" ]; then /bin/ps -o lstart= -p "$pid"; fi
        """).trimmingCharacters(in: .whitespacesAndNewlines)
        return output.isEmpty ? text("unknown") : output
    }

    private func zapretRuntime() -> String {
        let output = runShell("""
        pid=$(/usr/bin/pgrep -x tpws | /usr/bin/head -n 1)
        if [ -n "$pid" ]; then /bin/ps -o etimes= -p "$pid" | /usr/bin/xargs; fi
        """).trimmingCharacters(in: .whitespacesAndNewlines)
        if let seconds = TimeInterval(output) {
            return formatDuration(seconds)
        }
        return text("unknown")
    }

    private func timeSinceLastStop() -> String {
        let timestamp = UserDefaults.standard.double(forKey: stopTimeKey)
        if timestamp <= 0 {
            return text("never")
        }
        return formatDuration(Date().timeIntervalSince1970 - timestamp)
    }

    private func lastStopTime() -> String {
        let timestamp = UserDefaults.standard.double(forKey: stopTimeKey)
        if timestamp <= 0 {
            return text("never")
        }
        return formatDate(Date(timeIntervalSince1970: timestamp))
    }

    private func lastStartTime() -> String {
        let timestamp = UserDefaults.standard.double(forKey: startTimeKey)
        if timestamp <= 0 {
            return text("unknown")
        }
        return formatDate(Date(timeIntervalSince1970: timestamp))
    }

    private func formatDate(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = effectiveLanguage() == .ru ? Locale(identifier: "ru_RU") : Locale(identifier: "en_US")
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return formatter.string(from: date)
    }

    private func formatDateOnly(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = effectiveLanguage() == .ru ? Locale(identifier: "ru_RU") : Locale(identifier: "en_US")
        formatter.dateFormat = "yyyy-MM-dd"
        return formatter.string(from: date)
    }

    private func statusReport() -> String {
        let running = isZapretRunning()
        let restarting = restartingUntil.map { Date() < $0 } ?? false
        let statusLine = restarting ? text("humanRestarting") : (running ? text("humanRunning") : text("humanStopped"))
        let connectionLine = isInternetReachable() ? text("internetReachable") : text("internetUnreachable")
        let runtimeLine = running
            ? "\(text("runningSince")) \(zapretStartedAt())\n\(text("runningFor")) \(zapretRuntime())"
            : "\(text("lastStoppedAt")) \(lastStopTime())\n\(text("stoppedFor")) \(timeSinceLastStop())"

        let restartLine = running && isInternetReachable() ? text("restartAvailable") : text("restartBlocked")

        return """
        \(statusLine)
        \(connectionLine)

        \(runtimeLine)

        \(text("listsBlock"))
        \(text("lastListUpdate")) \(hostlistModifiedTime())
        \(text("mainListSize")) \(hostlistLineCount()) \(text("lines"))
        \(text("userListSize")) \(userHostlistLineCount()) \(text("lines"))

        \(text("startupBlock"))
        \(text("menuAutostart"))
        \(text("zapretNoAutostart"))

        \(text("actionsBlock"))
        \(restartLine)
        \(text("connectionCheckHint"))
        """
    }

    private func aboutText() -> String {
        """
        \(text("aboutTitle"))

        \(text("aboutDate")) \(formatDateOnly(Date()))
        \(text("aboutAppUpdated")) \(appModifiedDate())
        \(text("aboutListsUpdated")) \(hostlistModifiedDate())

        \(text("aboutWhat"))

        \(text("aboutHowToUse"))
        \(text("aboutStart"))
        \(text("aboutStop"))
        \(text("aboutRestart"))
        \(text("aboutConnection"))
        \(text("aboutUpdate"))
        \(text("aboutQuit"))
        """
    }

    private func formatDuration(_ seconds: TimeInterval) -> String {
        let total = max(0, Int(seconds))
        let days = total / 86400
        let hours = (total % 86400) / 3600
        let minutes = (total % 3600) / 60
        let secs = total % 60
        if days > 0 {
            return "\(days)d \(hours)h \(minutes)m"
        }
        if hours > 0 {
            return "\(hours)h \(minutes)m"
        }
        if minutes > 0 {
            return "\(minutes)m \(secs)s"
        }
        return "\(secs)s"
    }

    private func shellEscape(_ value: String) -> String {
        "'\(value.replacingOccurrences(of: "'", with: "'\\''"))'"
    }

    private func showDialog(_ message: String, title: String) {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = message
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }

    private func showNotification(_ message: String) {
        let content = UNMutableNotificationContent()
        content.title = "Zapret"
        content.body = message
        let request = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request)
    }

    private func selectedLanguage() -> Language {
        let rawValue = UserDefaults.standard.string(forKey: languageKey) ?? Language.auto.rawValue
        return Language(rawValue: rawValue) ?? .auto
    }

    private func effectiveLanguage() -> Language {
        let selected = selectedLanguage()
        if selected != .auto {
            return selected
        }

        let systemCode = Locale.preferredLanguages.first?.lowercased() ?? ""
        return systemCode.hasPrefix("ru") ? .ru : .en
    }

    private func languageMenuTitle() -> String {
        let current = effectiveLanguage() == .ru ? "Русский" : "English"
        let next = effectiveLanguage() == .ru ? "English" : "Русский"
        return "\(text("switchLanguage")): \(current) → \(next)"
    }

    private func text(_ key: String) -> String {
        let ru: [String: String] = [
            "start": "📳 Запустить",
            "stop": "📴 Остановить",
            "restart": "🔀 Перезапустить",
            "updateHostlist": "🔂 Обновить список",
            "checkConnection": "📶 Проверить соединение",
            "showStatus": "▶ Показать статус",
            "about": "ℹ️ О программе",
            "switchLanguage": "Переключить язык",
            "quit": "✖ Выключить программу",
            "statusRunning": "Статус: запущен",
            "statusStopped": "Статус: остановлен",
            "statusRestarting": "Статус: перезапускается",
            "started": "Zapret запущен",
            "stopped": "Zapret остановлен",
            "restarted": "Zapret перезапущен",
            "hostlistUpdated": "Список обновлён",
            "restartUnavailable": "Перезапуск доступен только когда zapret уже запущен. Сейчас соединение выключено.",
            "restartNoInternet": "Перезапуск заблокирован: интернет-соединение не проходит проверку.",
            "zapretRunningLine": "Zapret: запущен",
            "zapretStoppedLine": "Zapret: остановлен",
            "mainHostlist": "Основной список:",
            "userHostlist": "Пользовательский список:",
            "humanRunning": "📳 Zapret включён. Соединение сейчас работает через правила zapret.",
            "humanStopped": "📴 Zapret выключен. Дополнительные правила обхода сейчас не применяются.",
            "humanRestarting": "🔀 Zapret перезапускается. Подождите несколько секунд, пока правила применятся заново.",
            "internetReachable": "📶 Интернет доступен: проверка соединения проходит.",
            "internetUnreachable": "📶 Интернет недоступен: проверка соединения не проходит.",
            "runningSince": "Запущен:",
            "runningFor": "Работает уже:",
            "lastStoppedAt": "Последняя остановка:",
            "stoppedFor": "Выключен уже:",
            "listsBlock": "Списки обхода:",
            "mainListSize": "Основной список:",
            "userListSize": "Ваш ручной список:",
            "startupBlock": "Автозапуск:",
            "menuAutostart": "• меню Zapret запускается вместе с macOS",
            "zapretNoAutostart": "• сам zapret после перезагрузки остаётся выключенным",
            "actionsBlock": "Действия:",
            "restartAvailable": "• 🔀 Перезапуск доступен, потому что zapret включён",
            "restartBlocked": "• 🔀 Перезапуск заблокирован: zapret выключен или нет интернет-соединения",
            "connectionCheckHint": "• 📶 Проверка соединения проверяет доступность интернета, а не включает zapret",
            "startedAt": "Запущен:",
            "notRunning": "не запущен",
            "timeSinceLastStop": "Прошло с последней остановки:",
            "lastListUpdate": "Последнее обновление списка:",
            "lines": "строк",
            "unknown": "неизвестно",
            "never": "никогда",
            "before": "Было строк:",
            "after": "Стало строк:",
            "commandOutput": "Вывод команды:",
            "noOutput": "без вывода",
            "hostlistUpdateFailed": "Обновление списка завершилось с ошибкой",
            "statusUnavailable": "Статус недоступен",
            "commandFailed": "Команда не выполнена",
            "errorTitle": "Ошибка Zapret",
            "passwordlessSetupMissing": "Нет разрешения запускать zapret без пароля. Нужно один раз настроить правило sudoers.",
            "languageChanged": "Язык интерфейса переключён",
            "internetOk": "Интернет доступен.",
            "internetFailTitle": "Интернет недоступен",
            "internetFailMessage": "Не удалось подключиться к проверочным адресам. Можно остановить zapret или закрыть окно и проверить Wi‑Fi/VPN/DNS вручную.",
            "aboutTitle": "Zapret Menu — управление zapret из верхнего меню macOS.",
            "aboutDate": "Текущая дата:",
            "aboutAppUpdated": "Последнее обновление программы:",
            "aboutListsUpdated": "Последнее обновление списков доступа:",
            "aboutWhat": "Приложение управляет локальной установкой zapret: запускает, останавливает, перезапускает сервис и обновляет списки обхода.",
            "aboutHowToUse": "Как пользоваться:",
            "aboutStart": "• 📳 Запустить — включает zapret.",
            "aboutStop": "• 📴 Остановить — выключает zapret и очищает правила.",
            "aboutRestart": "• 🔀 Перезапустить — доступно только когда zapret уже включён и интернет проходит проверку.",
            "aboutConnection": "• 📶 Проверить соединение — проверяет доступность интернета через ping 1.1.1.1 и HTTPS-запрос к apple.com.",
            "aboutUpdate": "• 🔂 Обновить список — скачивает свежий список доменов обхода.",
            "aboutQuit": "• ✖ Выключить программу — сначала останавливает zapret, затем закрывает меню.",
            "close": "Закрыть"
        ]

        let en: [String: String] = [
            "start": "📳 Start",
            "stop": "📴 Stop",
            "restart": "🔀 Restart",
            "updateHostlist": "🔂 Update Hostlist",
            "checkConnection": "📶 Check Connection",
            "showStatus": "▶ Show Status",
            "about": "ℹ️ About",
            "switchLanguage": "Switch Language",
            "quit": "✖ Quit",
            "statusRunning": "Status: running",
            "statusStopped": "Status: stopped",
            "statusRestarting": "Status: restarting",
            "started": "Zapret started",
            "stopped": "Zapret stopped",
            "restarted": "Zapret restarted",
            "hostlistUpdated": "Hostlist updated",
            "restartUnavailable": "Restart is only available when zapret is already running. The connection is currently off.",
            "restartNoInternet": "Restart is blocked: the internet connection check is failing.",
            "zapretRunningLine": "Zapret: running",
            "zapretStoppedLine": "Zapret: stopped",
            "mainHostlist": "Main hostlist:",
            "userHostlist": "User hostlist:",
            "humanRunning": "📳 Zapret is on. The connection is currently using zapret rules.",
            "humanStopped": "📴 Zapret is off. Bypass rules are not applied right now.",
            "humanRestarting": "🔀 Zapret is restarting. Wait a few seconds while the rules are applied again.",
            "internetReachable": "📶 Internet is reachable: connection check passes.",
            "internetUnreachable": "📶 Internet is unreachable: connection check fails.",
            "runningSince": "Started:",
            "runningFor": "Running for:",
            "lastStoppedAt": "Last stopped:",
            "stoppedFor": "Stopped for:",
            "listsBlock": "Bypass lists:",
            "mainListSize": "Main list:",
            "userListSize": "Your manual list:",
            "startupBlock": "Startup:",
            "menuAutostart": "• Zapret Menu starts with macOS",
            "zapretNoAutostart": "• zapret itself stays off after reboot",
            "actionsBlock": "Actions:",
            "restartAvailable": "• 🔀 Restart is available because zapret is on",
            "restartBlocked": "• 🔀 Restart is blocked: zapret is off or internet is unavailable",
            "connectionCheckHint": "• 📶 Check Connection verifies internet reachability; it does not turn zapret on",
            "startedAt": "Started at:",
            "notRunning": "not running",
            "timeSinceLastStop": "Time since last stop:",
            "lastListUpdate": "Last hostlist update:",
            "lines": "lines",
            "unknown": "unknown",
            "never": "never",
            "before": "Before:",
            "after": "After:",
            "commandOutput": "Command output:",
            "noOutput": "no output",
            "hostlistUpdateFailed": "Hostlist update failed",
            "statusUnavailable": "Status unavailable",
            "commandFailed": "Command failed",
            "errorTitle": "Zapret Error",
            "passwordlessSetupMissing": "No permission to run zapret without a password. Configure the sudoers rule once.",
            "languageChanged": "Interface language switched",
            "internetOk": "Internet is available.",
            "internetFailTitle": "Internet unavailable",
            "internetFailMessage": "The test addresses are unreachable. You can stop zapret or close this window and check Wi-Fi/VPN/DNS manually.",
            "aboutTitle": "Zapret Menu — control zapret from the macOS menu bar.",
            "aboutDate": "Current date:",
            "aboutAppUpdated": "Last app update:",
            "aboutListsUpdated": "Last access list update:",
            "aboutWhat": "The app controls the local zapret installation: start, stop, restart, and hostlist update.",
            "aboutHowToUse": "How to use:",
            "aboutStart": "• 📳 Start — turns zapret on.",
            "aboutStop": "• 📴 Stop — turns zapret off and clears rules.",
            "aboutRestart": "• 🔀 Restart — available only when zapret is already on and the internet check passes.",
            "aboutConnection": "• 📶 Check Connection — checks internet reachability using ping to 1.1.1.1 and an HTTPS request to apple.com.",
            "aboutUpdate": "• 🔂 Update Hostlist — downloads a fresh bypass domain list.",
            "aboutQuit": "• ✖ Quit — stops zapret first, then closes the menu app.",
            "close": "Close"
        ]

        let dictionary = effectiveLanguage() == .ru ? ru : en
        return dictionary[key] ?? key
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.run()
