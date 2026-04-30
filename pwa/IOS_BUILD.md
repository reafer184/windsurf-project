# Сборка iOS приложения (.ipa)

Эта инструкция поможет скомпилировать PWA в нативное iOS приложение через Capacitor.

## Требования

- macOS (только на Mac можно собрать .ipa)
- Xcode 15+ (установить из App Store)
- Node.js 22+ (проверить: `node --version`)
- Apple Developer аккаунт ($99/год для публикации в App Store)
  - Или бесплатный аккаунт для установки на свой iPhone

## Шаг 1: Подготовка на macOS

```bash
# Установите Node.js 22+ (если нужно)
brew install node@22

# Или через nvm:
nvm install 22
nvm use 22
```

## Шаг 2: Установка зависимостей

```bash
cd pwa/
npm install
```

## Шаг 3: Добавление iOS платформы

```bash
# Инициализация Capacitor (один раз)
npx cap init "TOTP Authenticator" ru.totp.authenticator --web-dir . --force

# Добавление iOS (один раз)
npx cap add ios

# Синхронизация при изменениях в веб-коде
npx cap sync ios
```

После этого появится папка `ios/` с Xcode проектом.

## Шаг 4: Настройка Xcode

1. Откройте проект:
```bash
npx cap open ios
```

2. В Xcode настройте:
   - **Signing & Capabilities** → выберите свою Team
   - **Bundle Identifier** → `ru.totp.authenticator` (или свой)
   - **Deployment Target** → iOS 16.0+

## Шаг 5: Сборка

### Вариант А: Запуск на своём iPhone (бесплатно)

1. Подключите iPhone к Mac
2. В Xcode: Window → Devices and Simulators → проверьте что устройство видно
3. Нажмите ▶️ (Run) — приложение установится на телефон

**Важно:** Бесплатный аккаунт требует переустановки каждые 7 дней.

### Вариант Б: Сборка .ipa для установки

1. В Xcode выберите: Product → Destination → Generic iOS Device
2. Product → Archive
3. Window → Organizer → Archives → Distribute App
4. Выберите:
   - **Development** — для тестирования на устройствах
   - **Ad Hoc** — для установки на зарегистрированные устройства
   - **App Store** — для публикации

### Вариант В: Консольная сборка (CI/CD)

```bash
# Создать .xcarchive
xcodebuild -workspace ios/App/App.xcworkspace \
  -scheme App \
  -sdk iphoneos \
  -configuration Release \
  archive -archivePath build/App.xcarchive

# Экспорт .ipa
xcodebuild -exportArchive \
  -archivePath build/App.xcarchive \
  -exportOptionsPlist exportOptions.plist \
  -exportPath build/
```

Создайте `exportOptions.plist`:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>method</key>
    <string>development</string>
    <key>teamID</key>
    <string>YOUR_TEAM_ID</string>
    <key>compileBitcode</key>
    <false/>
    <key>stripSwiftSymbols</key>
    <true/>
</dict>
</plist>
```

## Шаг 6: Установка .ipa на устройство

### Способ 1: Apple Configurator 2 (бесплатно)
1. Установите [Apple Configurator 2](https://apps.apple.com/us/app/apple-configurator-2/id1037126344) из Mac App Store
2. Подключите iPhone
3. Двойной клик на устройство → Apps → Add → выберите .ipa

### Способ 2: AltStore / Sideloadly (бесплатно, для тестирования)
- [AltStore](https://altstore.io/) — установка без Mac
- [Sideloadly](https://sideloadly.io/) — через компьютер

### Способ 3: TestFlight (для бета-тестеров)
- Загрузите в App Store Connect
- Пригласите до 100 тестеров по email
- Без модерации, автоматически

### Способ 4: App Store (публикация)
- Подготовьте скриншоты, описание, иконки
- Загрузите через Xcode → Organizer → Distribute
- Ожидайте модерации Apple (1-2 дня)

## Использование нативных плагинов

Capacitor позволяет использовать нативные API. Пример интеграции в `app.js`:

```javascript
import { Camera } from '@capacitor/camera';
import { Preferences } from '@capacitor/preferences';

// Вместо getUserMedia — нативная камера
const scanQR = async () => {
  const photo = await Camera.getPhoto({
    quality: 90,
    allowEditing: false,
    resultType: 'base64'
  });
  // Обработка QR...
};

// Вместо localStorage — нативное хранилище (более надёжное)
const saveSecret = async (secret) => {
  await Preferences.set({
    key: 'secret',
    value: JSON.stringify(secret)
  });
};
```

## Решение проблем

### "Could not find module 'Capacitor'"
```bash
cd ios/App
pod install --repo-update
```

### "Signing for \"App\" requires a development team"
В Xcode: Signing & Capabilities → Team → выберите свой Apple ID

### "The app ID cannot be registered"
Bundle ID уже занят. Измените в `capacitor.config.json`:
```json
"appId": "ru.yourname.totpauth"
```

### QR-сканер не работает в нативном приложении
Замените `getUserMedia` на Capacitor Camera плагин (см. пример выше).

## Оптимизация под iOS

### Status bar
Добавьте в `capacitor.config.json`:
```json
"ios": {
  "statusBarStyle": "DARK_CONTENT",
  "hideStatusBar": false
}
```

### Safe area (чёлка, Dynamic Island)
В `styles.css` уже есть поддержка `env(safe-area-inset-*)`.

### Жесты
iOS перехватывает свайпы. Добавьте в `index.html`:
```html
<meta name="viewport" content="... viewport-fit=cover">
```

## Сравнение с PWA

| | PWA в браузере | .ipa через Capacitor |
|---|---|---|
| Установка | Через Safari | App Store / AltStore |
| Офлайн | ✅ (Service Worker) | ✅ (встроено) |
| Камера | getUserMedia | Нативный API (лучше) |
| Хранилище | IndexedDB | Keychain (безопаснее) |
| Push-уведомления | ⚠️ Ненадёжно | ✅ Нативные |
| Face ID / Touch ID | ❌ | ✅ Можно добавить |
| Автообновление | Мгновенно | Через App Store |

## Дальнейшие шаги

1. Протестируйте на симуляторе: `npx cap run ios`
2. Проверьте производительность на реальном устройстве
3. Добавьте иконки и splash screen в `ios/App/App/Assets.xcassets`
4. Настройте Code Signing для распространения

---

**Требуется помощь?** Могу добавить нативные плагины для камеры и keychain, или настроить автоматическую сборку через GitHub Actions.
