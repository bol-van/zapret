# Zapret Menu for macOS

> **Attention**
>
> Это репозиторий fork от версии `zapret`. В данной адаптации для macOS добавлена совместимость с macOS и визуальный интерфейс для удобной работы без ручного запуска скриптов.
>
> **P.S.** Человек не написал ни одной строки добавленного кода вручную; всё было сделано Cursor + GPT-5.5.
>
> This repository is a fork/adaptation of `zapret`. This macOS-oriented solution adds compatibility notes for macOS usage and a visual menu bar interface so users can work with zapret without manually running shell scripts.
>
> **P.S.** No human wrote a single line of this added code manually; it was generated and assembled with Cursor + GPT-5.5.

Optional macOS menu bar controller for a local zapret installation.

The app lives in the macOS menu bar and provides:

- start, stop, and restart controls;
- hostlist update;
- connection check;
- human-readable status;
- Russian/English interface switch;
- launch at user login while keeping zapret itself off after reboot.

## Requirements

- macOS;
- Xcode Command Line Tools (`swiftc`);
- zapret installed at `/opt/zapret` (or another path via `ZAPRET_BASE`);
- administrator account for installing the helper and sudoers rule.

Install Command Line Tools if needed:

```sh
xcode-select --install
```

## Install

From the repository root:

```sh
extras/macos-menu/install.sh
```

Custom zapret location:

```sh
ZAPRET_BASE=/opt/zapret extras/macos-menu/install.sh
```

Custom app install directory:

```sh
INSTALL_DIR="$HOME/Applications/Zapret Control" extras/macos-menu/install.sh
```

The installer:

1. Builds `Zapret Menu.app`.
2. Copies it to `$HOME/Applications/Zapret Control`.
3. Installs `/opt/zapret/zapret-menu-helper`.
4. Adds a limited sudoers rule in `/etc/sudoers.d/zapret-menu`.
5. Adds a user LaunchAgent so the menu app starts at login.

## Security note

The menu app needs elevated privileges because zapret controls PF rules and root-owned daemons.

The installer does **not** grant broad passwordless sudo. It grants passwordless access only to:

```text
/opt/zapret/zapret-menu-helper start
/opt/zapret/zapret-menu-helper stop
/opt/zapret/zapret-menu-helper restart
/opt/zapret/zapret-menu-helper update
```

The sudoers file is validated with `visudo -cf` before installation.

## Use

Menu bar icons:

- `📳` zapret is running;
- `📴` zapret is stopped;
- `🔀` zapret is restarting.

Menu actions:

- `📳 Start` starts zapret.
- `📴 Stop` stops zapret and clears rules.
- `🔀 Restart` refreshes zapret only when it is already running and internet check passes.
- `🔂 Update Hostlist` downloads the domain list.
- `📶 Check Connection` checks internet reachability with ping to `1.1.1.1` and HTTPS request to `apple.com`.
- `▶ Show Status` shows runtime, last stop, list update date, and list sizes.
- `ℹ️ About` shows app dates and a short usage guide.
- `✖ Quit` stops zapret first, verifies it stopped, then closes the menu app.

## Uninstall

```sh
extras/macos-menu/uninstall.sh
```

The uninstaller removes:

- user LaunchAgent;
- menu app bundle;
- privileged helper;
- sudoers rule.

It does not remove zapret itself.

## Build only

```sh
extras/macos-menu/build.sh
```

The built app is written to:

```text
extras/macos-menu/build/Zapret Menu.app
```
