# TOTP Authenticator MVP

MVP-проект по ТЗ: backend (Express + Prisma + PostgreSQL) и базовый PWA-клиент.

## Быстрый старт

1. Скопируй переменные:
   - `cp .env.example .env`
   - заполни в `.env`: `DB_PASSWORD`, `JWT_ACCESS_SECRET`, `JWT_REFRESH_SECRET`
2. Запусти сервисы:
   - `docker compose up --build -d`

`docker-compose` запускает API только после готовности PostgreSQL и выполняет `prisma db push` перед стартом сервера.

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
