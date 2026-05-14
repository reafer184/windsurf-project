# TOTP Authenticator — Android APK

Автономный генератор TOTP-кодов (аналог Google Authenticator) в виде нативного Android-приложения.
Работает **полностью без сервера** — все секреты хранятся локально на устройстве.

## Возможности

- 🔐 Генерация TOTP-кодов (RFC 6238, SHA-1, 6 знаков)
- 📷 Сканирование QR-кодов через камеру
- 💾 Хранение в IndexedDB, зашифрованное мастер-паролем
- 📦 Экспорт / Импорт аккаунтов (JSON)
- 📵 Полный офлайн-режим (Service Worker)
- 🔒 Нет сервера, нет регистрации, нет передачи данных

## Структура проекта

```
pwa/
├── android/              ← нативный Android-проект (Capacitor)
├── www/                  ← скомпилированные веб-ассеты (копируются в APK)
├── index.html            ← UI приложения
├── app.js                ← основная логика
├── db.js                 ← локальная БД (IndexedDB)
├── gost.js               ← криптография ГОСТ
├── styles.css            ← стили
├── sw.js                 ← Service Worker (офлайн)
├── manifest.json         ← PWA-манифест
├── capacitor.config.json ← конфиг Capacitor (appId, webDir)
└── package.json          ← зависимости (@capacitor/android ^8.3.1)
```

## Сборка APK

### Требования
- Node.js 18+
- Android Studio (с Android SDK)
- Java 17+

### Шаги

```bash
cd pwa

# Установить зависимости
npm install

# Синхронизировать веб-ассеты с Android-проектом
npx cap sync android

# Debug APK
cd android
./gradlew assembleDebug
# APK: android/app/build/outputs/apk/debug/app-debug.apk

# Release APK (требует подписи)
./gradlew assembleRelease
```

### Открыть в Android Studio

```bash
cd pwa
npm run android:open
```

## Информация о приложении

| Параметр | Значение |
|----------|----------|
| App ID | `ru.totp.authenticator` |
| Название | TOTP Authenticator |
| Движок | Capacitor 8.3.1 |
| Схема | `https` (androidScheme) |
| Cleartext | отключён |
| Разрешения | `CAMERA` |

## Безопасность

| Аспект | Реализация |
|--------|------------|
| Хранение секретов | IndexedDB, зашифровано мастер-паролем |
| Шифрование | XOR с производным ключом |
| Передача данных | ❌ Отсутствует |
| Мастер-пароль | Только в `sessionStorage`, никуда не отправляется |

## Бэкап

Оригинальный проект (включая удалённые `server/`, `client/`, docker-конфиги) сохранён в ветке:
[`backup/before-android-cleanup`](https://github.com/reafer184/windsurf-project/tree/backup/before-android-cleanup)
