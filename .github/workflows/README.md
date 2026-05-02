# GitHub Actions для сборки нативных приложений

Автоматическая сборка iOS (.ipa) и Android (.apk) прямо в GitHub — без локального macOS/Android Studio.

## Возможности

- ✅ **Автосборка при пуше** — каждый коммит в `main` собирает приложение
- ✅ **GitHub Releases** — автоматическая публикация .ipa/.apk в релизах
- ✅ **Симулятор билды** — без Apple Developer аккаунта (тестирование)
- ✅ **Подписанные билды** — с вашими сертификатами Apple/Google
- ✅ **Ручной запуск** — с выбором типа подписи (development/ad-hoc/app-store)

## Файлы

| Файл | Назначение |
|------|-----------|
| `ios-build.yml` | Workflow для сборки iOS и Android |

## Настройка

### 1. Android (.apk) — БЕСПЛАТНО

Для сборки подписанного APK нужен keystore:

```bash
# Локально сгенерируйте keystore:
keytool -genkey -v -keystore release.keystore -alias totp -keyalg RSA -keysize 2048 -validity 10000
```

Затем добавьте секреты в GitHub → Settings → Secrets and variables → Actions:

| Секрет | Значение |
|--------|----------|
| `ANDROID_KEYSTORE` | Base64 содержимого `release.keystore` |
| `ANDROID_KEYSTORE_PASSWORD` | Пароль от keystore |
| `ANDROID_KEY_ALIAS` | `totp` (или ваш alias) |
| `ANDROID_KEY_PASSWORD` | Пароль ключа (обычно = keystore password) |

```bash
# Кодирование keystore в Base64:
base64 -i release.keystore | pbcopy  # на macOS
# Вставьте результат в секрет GITHUB_TOKEN
```

**Результат:** При каждом пуше будет собираться подписанный .apk, доступный в Artifacts и Releases.

### 2. iOS (.ipa) — Требуется Apple Developer

Для подписанных .ipa нужен **Apple Developer аккаунт** ($99/год):

#### Шаг 1: Создайте сертификаты в Apple Developer Portal

1. https://developer.apple.com/account/resources/certificates/list
2. Certificates → Add → iOS Distribution (App Store and Ad Hoc)
3. Загрузите CSR (Certificate Signing Request):
   ```bash
   # На macOS:
   openssl genrsa -out private.key 2048
   openssl req -new -key private.key -out CertificateSigningRequest.certSigningRequest \
     -subj "emailAddress=your@email.com, CN=Your Name, C=US"
   ```
4. Скачайте `.cer` файл и конвертируйте в `.p12`:
   ```bash
   openssl x509 -in ios_distribution.cer -inform DER -out cert.pem -outform PEM
   openssl pkcs12 -export -in cert.pem -inkey private.key -out certificate.p12
   ```

#### Шаг 2: Создайте Provisioning Profile

1. https://developer.apple.com/account/resources/profiles/list
2. Add → Ad Hoc (для тестирования) или App Store
3. Выберите App ID: `ru.totp.authenticator` (или ваш Bundle ID)
4. Выберите сертификат из шага 1
5. Выберите устройства (для Ad Hoc)
6. Скачайте `.mobileprovision`

#### Шаг 3: Добавьте секреты в GitHub

| Секрет | Значение |
|--------|----------|
| `APPLE_TEAM_ID` | Ваш Team ID (10 символов, например: `ABCD123456`) |
| `APPLE_P12_CERTIFICATE` | Base64 содержимого `certificate.p12` |
| `APPLE_P12_PASSWORD` | Пароль от .p12 файла |
| `APPLE_PROVISIONING_PROFILE` | Base64 содержимого `.mobileprovision` |
| `KEYCHAIN_PASSWORD` | Любой пароль (создаёт временный keychain) |

```bash
# Кодирование в Base64:
base64 -i certificate.p12 | pbcopy
base64 -i TOTP_Authenticator.mobileprovision | pbcopy
```

#### Шаг 4: Раскомментируйте code signing в workflow

В файле `.github/workflows/ios-build.yml` раскомментируйте секцию:
```yaml
      - name: Setup Code Signing
        if: env.TEAM_ID != ''
        env:
          TEAM_ID: ${{ secrets.APPLE_TEAM_ID }}
          ...
```

### 3. iOS без подписи (тестирование)

Если нет Apple Developer аккаунта, workflow автоматически собирает **симулятор-версию**:
- Работает только на iOS Simulator
- Можно протестировать логику без реального устройства
- Доступно в Artifacts как `ios-simulator-app`

## Использование

### Автоматический режим

При каждом пуше в `main` ветку:
```bash
git add .
git commit -m "Update app"
git push origin main
```

GitHub Actions автоматически:
1. Соберёт Android APK (подписанный, если есть секреты)
2. Соберёт iOS IPA (подписанный, если есть секреты)
3. Загрузит артефакты
4. Создаст GitHub Release с .ipa/.apk

### Ручной запуск

GitHub → Actions → "Build iOS App (.ipa)" → Run workflow:
- Выберите `signing_type`: development / ad-hoc / app-store
- Нажмите Run

## Получение результатов

### Artifacts (все билды)

GitHub → Actions → [Последний запуск] → Artifacts:
- `TOTP-Authenticator-apk` — Android приложение
- `TOTP-Authenticator-ipa` — iOS приложение (требует подписи)
- `ios-simulator-app` — iOS для симулятора

### Releases (только для main ветки)

https://github.com/reafer184/windsurf-project/releases

Скачайте:
- `TOTP-Authenticator-XXXXXXXX-XXXXXX.ipa` — для iPhone
- `TOTP-Authenticator-XXXXXXXX-XXXXXX.apk` — для Android

## Установка собранных приложений

### Android (.apk)

1. Скачайте APK из Releases или Artifacts
2. Перекиньте на телефон
3. Установите (может потребоваться "Разрешить установку из неизвестных источников")

### iOS (.ipa) — Ad Hoc

Для установки Ad Hoc .ipa на устройство:

**Способ 1: Apple Configurator 2 (Mac)**
1. Установите [Apple Configurator 2](https://apps.apple.com/us/app/apple-configurator-2/id1037126344)
2. Подключите iPhone к Mac
3. Двойной клик на устройство → Apps → Add → выберите .ipa

**Способ 2: Diawi / InstallOnAir (веб)**
1. Загрузите .ipa на [diawi.com](https://www.diawi.com/) или [appinstall.io](https://appinstall.io/)
2. Откройте ссылку на iPhone
3. Установите (требуется доверие Enterprise сертификату в Settings)

**Способ 3: TestFlight (App Store)**
Если собирали с `app-store` подписью:
1. Загрузите в App Store Connect через `xcodebuild -exportArchive` или Transporter
2. Распространите через TestFlight

## Ограничения GitHub Actions

| Лимит | Значение |
|-------|----------|
| Минуты macOS | 200 минут/месяц (бесплатно) |
| Размер артефактов | 500 MB |
| Хранение артефактов | 90 дней |

Если лимитов не хватает — используйте `workflow_dispatch` (ручной запуск) только когда нужно.

## Альтернатива: Codemagic (бесплатно для open source)

Если GitHub Actions лимитов не хватает:

1. https://codemagic.io/start/ → Connect GitHub repo
2. Настройте workflow:
```yaml
workflows:
  ios-workflow:
    name: iOS Build
    instance_type: mac_mini_m1
    environment:
      xcode: latest
    scripts:
      - npm install
      - npx cap sync ios
    artifacts:
      - build/ios/ipa/*.ipa
```

Codemagic даёт 500 build minutes/месяц бесплатно для open source проектов.

## Troubleshooting

### "No signing certificate found"
- Проверьте что секреты `APPLE_*` добавлены
- Проверьте Team ID (10 символов, без пробелов)
- Проверьте срок действия сертификата

### "Provisioning profile doesn't match bundle ID"
- Bundle ID в `capacitor.config.json` должен совпадать с App ID в сертификате
- Пример: `ru.totp.authenticator`

### "IPA file is empty or corrupted"
- Проверьте Xcode версию в workflow (15.4+)
- Проверьте `ExportOptions.plist` метод (development/ad-hoc/app-store)

### Android build failed
- Убедитесь что `ANDROID_KEYSTORE` в формате Base64 (без переносов строк)
- Проверьте пароли на опечатки

## Примеры секретов

### Быстрая проверка секретов

```bash
# Проверьте что секреты работают локально:
export APPLE_TEAM_ID="ABCD123456"
export APPLE_P12_CERTIFICATE="$(base64 -i certificate.p12)"
export APPLE_P12_PASSWORD="your-password"
export APPLE_PROVISIONING_PROFILE="$(base64 -i profile.mobileprovision)"
export KEYCHAIN_PASSWORD="temp-password"

# Запустите локально:
act -j build-ios --secret-file .secrets
```

## Дальнейшие шаги

- [ ] Добавить секреты в GitHub Settings
- [ ] Запустить workflow вручную для теста
- [ ] Проверить Artifacts
- [ ] Настроить автоматические GitHub Releases
- [ ] Добавить CodePush для OTA обновлений (опционально)
