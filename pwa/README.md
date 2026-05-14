# TOTP Authenticator (PWA → Android APK)

Автономный генератор TOTP-кодов, собираемый в нативный Android APK через Capacitor.
Работает без сервера — все данные хранятся локально на устройстве.

## Особенности

- ✅ **Без сервера** — не требует бэкенда, интернета или регистрации
- ✅ **Локальное хранение** — секреты в IndexedDB, зашифрованные мастер-паролем
- ✅ **Совместим с Google Authenticator** — RFC 6238, любые TOTP QR-коды
- ✅ **Сканирование QR** — нативная камера Android
- ✅ **Экспорт / Импорт** — резервные копии в JSON
- ✅ **Офлайн** — Service Worker, работает без сети

## Сборка APK

### Требования
- Node.js 18+
- Android Studio + Android SDK
- Java 17+

### Команды

```bash
# Из папки pwa/
npm install
npx cap sync android        # синхронизация www/ → android/

# Debug сборка
cd android
./gradlew assembleDebug
# Результат: app/build/outputs/apk/debug/app-debug.apk

# Открыть в Android Studio
npm run android:open
```

## Добавление аккаунта

**Способ 1 — Сканировать QR:**
1. Разблокируйте приложение мастер-паролем
2. Нажмите «Сканировать QR»
3. Наведите камеру на QR-код из настроек 2FA

**Способ 2 — Вручную:**
1. Введите название сервиса и имя аккаунта
2. Вставьте Base32-секрет из настроек 2FA
3. Нажмите «Добавить»

## Резервная копия

- **Экспорт** — кнопка в приложении, скачивается JSON со всеми аккаунтами
- **Импорт** — восстановление из JSON при смене устройства или сбросе
- Храните экспорт в надёжном месте (облако, зашифрованный флешка)

## Технологии

| Стек | Версия |
|------|--------|
| Capacitor Android | ^8.3.1 |
| Capacitor Core | ^8.3.1 |
| Capacitor Camera | ^8.2.0 |
| Capacitor Preferences | ^8.0.1 |
| IndexedDB | браузерный API |
| Web Crypto API | браузерный API |
| Service Worker | браузерный API |
| JavaScript | Vanilla (без фреймворков) |

## Безопасность

| Аспект | Реализация |
|--------|------------|
| Хранение секретов | IndexedDB, зашифровано мастер-паролем |
| Шифрование | XOR с производным ключом |
| Передача данных | ❌ Отсутствует — всё остаётся на устройстве |
| Мастер-пароль | Только в `sessionStorage`, никуда не отправляется |
| HTTPS-схема | `androidScheme: https` в Capacitor |
| Cleartext | Отключён (`cleartext: false`) |

## Конфиг Capacitor

```json
{
  "appId": "ru.totp.authenticator",
  "appName": "TOTP Authenticator",
  "webDir": "www",
  "server": {
    "androidScheme": "https",
    "cleartext": false
  },
  "plugins": {
    "Camera": { "permissions": ["camera"] }
  }
}
```

## npm scripts

```bash
npm run sync            # npx cap sync
npm run android:add     # добавить Android платформу
npm run android:open    # открыть в Android Studio
npm run android:build   # sync + сборка
```
