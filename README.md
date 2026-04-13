# TOTP Authenticator MVP

MVP-проект по ТЗ: backend (Express + Prisma + PostgreSQL) и базовый PWA-клиент.

## Быстрый старт

1. Скопируй переменные:
   - `cp .env.example .env`
   - `cp server/.env.example server/.env`
2. Запусти сервисы:
   - `docker compose up --build`
3. В отдельном терминале накатить миграции Prisma:
   - `docker compose exec api npx prisma migrate dev --name init`

## URL

- PWA: `http://localhost`
- API: `http://localhost/api/v1`
- Health: `http://localhost/health`

## Что реализовано

- JWT auth (`register/login/refresh/logout/me/change-password`)
- CRUD TOTP аккаунтов
- Управление устройствами (refresh токены)
- Аудит-лог базовых действий
- Клиентская генерация TOTP (RFC6238, SHA-1, 6 знаков)
