# S.O.W.A Security Software

<p align="center">
  <img src="https://raw.githubusercontent.com/AristarhUcolov/CNS-SOWA-DNS-BLACKLIST-FILTERING/main/blacklist/../README.md" alt="S.O.W.A" width="200">
</p>

[![GitHub license](https://img.shields.io/github/license/AristarhUcolov/CNS-SOWA-SECURITY)](https://github.com/AristarhUcolov/CNS-SOWA-SECURITY/blob/main/LICENSE)

## 🇷🇺 RU

### 🔐 S.O.W.A Security Software — DNS-защита и фильтрация

**S.O.W.A Security Software** — полнофункциональное программное обеспечение для DNS-фильтрации и защиты, разработанное организацией **C.N.S (Clear Net Sky)**.

### ✨ Возможности

- 🛡️ **Блокировка рекламы и трекеров** — 29+ категорий блокировочных списков
- 🔒 **Зашифрованный DNS** — DNS-over-HTTPS (DoH), DNS-over-TLS (DoT), DNSCrypt
- 🔍 **Безопасный поиск** — принудительный Safe Search на всех поисковиках (Google, Bing, Yandex, DuckDuckGo, Yahoo, YouTube, Ecosia, StartPage, Brave)
- 👨‍👩‍👧‍👦 **Родительский контроль** — блокировка контента для взрослых
- 🌐 **DHCP-сервер** — встроенный DHCP
- 📊 **Статистика и логи** — подробная статистика DNS-запросов
- 💻 **Веб-интерфейс** — удобная панель управления в стиле C.N.S
- 📋 **Настраиваемые списки** — чёрные, белые списки и пользовательские правила
- 👤 **Per-device конфигурация** — настройки для каждого устройства
- 🔐 **Контроль доступа** — разрешённые/запрещённые клиенты
- 🌍 **IPv4 и IPv6** — полная поддержка обоих протоколов
- 📦 **Один EXE** — работает как портативное приложение

### 🚀 Быстрый старт

1. Скачайте `sowa-security.exe` из [Releases](https://github.com/AristarhUcolov/CNS-SOWA-SECURITY/releases)
2. Запустите EXE файл
3. Откройте браузер: `http://localhost:8080`
4. Настройте DNS вашего устройства на `127.0.0.1`

### 🔧 Сборка из исходников

```bash
git clone https://github.com/AristarhUcolov/CNS-SOWA-SECURITY.git
cd CNS-SOWA-SECURITY
go mod tidy
go build -o sowa-security.exe ./cmd/sowa/
```

Или используйте `build.bat` на Windows.

### 📂 Структура проекта

```
├── cmd/sowa/           # Точка входа приложения
├── internal/
│   ├── api/            # REST API и веб-сервер
│   ├── config/         # Конфигурация
│   ├── dhcp/           # DHCP-сервер
│   ├── dnsserver/      # DNS-сервер (UDP/TCP)
│   ├── filtering/      # Движок фильтрации
│   └── stats/          # Статистика и логи
├── web/                # Веб-интерфейс (HTML/CSS/JS)
├── data/               # Данные (списки, конфиг, статистика)
│   ├── blacklist/      # Кэш чёрных списков
│   ├── whitelist/      # Кэш белых списков
│   └── config/         # Конфигурация и статистика
└── build/              # Скомпилированные файлы
```

---

## 🇬🇧 ENG

### 🔐 S.O.W.A Security Software — DNS Protection & Filtering

**S.O.W.A Security Software** — full-featured DNS filtering and protection software developed by **C.N.S (Clear Net Sky)** organization.

### ✨ Features

- 🛡️ **Block ads and trackers** — 29+ categories of blocklists
- 🔒 **Encrypted DNS** — DNS-over-HTTPS (DoH), DNS-over-TLS (DoT), DNSCrypt
- 🔍 **Safe Search** — enforce Safe Search on all search engines (Google, Bing, Yandex, DuckDuckGo, Yahoo, YouTube, Ecosia, StartPage, Brave)
- 👨‍👩‍👧‍👦 **Parental Control** — block adult content domains
- 🌐 **Built-in DHCP Server**
- 📊 **Statistics & Query Log** — detailed DNS query statistics
- 💻 **Web Interface** — modern admin dashboard in C.N.S style
- 📋 **Customizable Lists** — blocklists, whitelists, and custom rules
- 👤 **Per-client (device) configuration**
- 🔐 **Access Control** — allowed/disallowed clients
- 🌍 **IPv4 and IPv6** — full dual-stack support
- 📦 **Single EXE** — runs as a portable application

### 🚀 Quick Start

1. Download `sowa-security.exe` from [Releases](https://github.com/AristarhUcolov/CNS-SOWA-SECURITY/releases)
2. Run the EXE file
3. Open browser: `http://localhost:8080`
4. Set your device's DNS to `127.0.0.1`

### 🔧 Build from Source

```bash
git clone https://github.com/AristarhUcolov/CNS-SOWA-SECURITY.git
cd CNS-SOWA-SECURITY
go mod tidy
go build -o sowa-security.exe ./cmd/sowa/
```

Or use `build.bat` on Windows.

### 🔗 Links

- 🌐 [Clear Net Sky Website](https://aristarhucolov.github.io/C.N.S-Clear.Net.Sky-S.O.W.A/)
- 📋 [DNS Blacklist Filtering](https://github.com/AristarhUcolov/CNS-SOWA-DNS-BLACKLIST-FILTERING)
- 🔐 [S.O.W.A Security](https://github.com/AristarhUcolov/CNS-SOWA-SECURITY)

### 📜 License

GPL-3.0

### 👥 Team

Developed by **C.N.S (Clear Net Sky)** in collaboration with **S.A** and **OpcoderZ-Security**.
