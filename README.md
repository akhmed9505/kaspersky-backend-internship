# Information Exchange Service

REST API на Go для хранения и обновления сведений о файловых угрозах по готовому MD5-хешу. Позволяет создавать, получать и обновлять записи по MD5-хешу. Данные хранятся в PostgreSQL, доступ к API защищён HTTPS и API-ключом.

## Описание

Клиент передаёт MD5 и сведения об угрозе. MD5 служит уникальным идентификатором:
принимается в любом регистре, сохраняется и возвращается в lowercase.

| Метод | Путь | Назначение |
|---|---|---|
| `POST` | `/info` | Создать запись; повторный MD5 возвращает `409` |
| `GET` | `/info/{md5}` | Получить запись; отсутствующая возвращает `404` |
| `PUT` | `/info/{md5}` | Полностью заменить изменяемые поля существующей записи |

Полные схемы запросов, ответов и правила валидации — в [openapi.yaml](openapi.yaml).

## Возможности

- Хранение названия, описания, уровня опасности, типа файла и времени первого обнаружения.
- Строгая проверка JSON: обязательные поля, точный регистр ключей, запрет дублей, неизвестных полей и `null`.
- Уникальность MD5 на уровне PostgreSQL, в том числе при конкурентном создании записей.
- HTTPS с TLS 1.2+, API Key и два уровня rate limiting.
- Ограничения размеров запросов, таймауты, структурированные логи и graceful shutdown.
- Unit-тесты и интеграционные тесты с реальными PostgreSQL и HTTPS.

## Технологии

- **Go 1.27** — язык и стандартный HTTP-сервер `net/http`.
- **PostgreSQL 17** — постоянное хранение данных.
- **pgx/v5** — PostgreSQL-драйвер и пул соединений.
- **OpenAPI 3.0 / oapi-codegen v2.8.1** — контракт, генерация DTO и маршрутов.
- **golang-migrate** — версионированные SQL-миграции.
- **golang.org/x/time/rate** — локальные token bucket limiter.
- **log/slog** — структурированные JSON-логи.
- **Docker Compose** — запуск приложения, миграций и изолированной тестовой среды.
- **testing / httptest** — тестирование стандартными средствами Go.

## Архитектура

- `cmd/server` — точка входа и обработка сигналов завершения.
- `internal/app` — создание зависимостей и управление жизненным циклом.
- `internal/config` — чтение и проверка переменных окружения.
- `internal/domain` — бизнес-модели и независимая валидация.
- `internal/service/threat` — сценарии Create/Get/Update и интерфейс репозитория.
- `internal/repository` — параметризованные SQL-запросы.
- `internal/infra/postgres` — настройка пула PostgreSQL.
- `internal/delivery/http` — обработчики, преобразование DTO и middleware.
- `migrations` и `tests/integration` — SQL-миграции и интеграционные тесты.

Направление зависимостей: **HTTP → Service → Domain**. PostgreSQL-репозиторий
реализует интерфейс сервиса. Домен не зависит от HTTP, PostgreSQL и сгенерированных DTO.

## Запуск

### Требования

- Docker Engine и Docker Compose v2+.
- Make и OpenSSL 3+.
- curl для примеров запросов.
- Go 1.27+ для локальных тестов; C-компилятор для race detector.

### Настройка окружения

При первой настройке выполните из корня проекта:

```bash
cp .env.example .env
chmod 600 .env
```

Если `.env` уже настроен, не заменяйте его шаблоном. Заполните три пустых значения:

| Переменная | Назначение |
|---|---|
| `API_KEY` | Случайный ключ: минимум 32 печатных ASCII-символа без пробелов |
| `DB_PASSWORD` | Непустой пароль отдельной роли приложения |
| `POSTGRES_PASSWORD` | Отдельный пароль администратора PostgreSQL; приложению не передаётся |

Для каждого значения можно получить независимый секрет:

```bash
openssl rand -hex 32
```

Остальные параметры и TLS-пути заданы в [.env.example](.env.example).
Compose читает локальный `.env` и явно передаёт переменные нужным сервисам.
Go-приложение **не загружает `.env` автоматически**.

### Локальный TLS-сертификат

```bash
sh scripts/dev-setup.sh
```

Скрипт создаёт самоподписанный сертификат на 30 дней и приватный ключ вне репозитория.
SAN включает `localhost`, `app` и `127.0.0.1`. Файлы монтируются в контейнер read-only.

Если TLS-файлы уже существуют, пропустите этот шаг: скрипт не перезаписывает их.
Для другого каталога передайте его скрипту первым аргументом и обновите
`TLS_CERT_FILE` и `TLS_KEY_FILE` в `.env`.

### Запуск и остановка

```bash
make compose-config
make up
```

`make up` собирает образ и запускает PostgreSQL, затем миграции и HTTPS-сервер.
Адрес API: **https://localhost:8443**. Во всех запросах нужен заголовок
`X-API-Key` со значением `API_KEY`.

Наружу публикуется только `127.0.0.1:8443`. PostgreSQL-порты не публикуются;
Compose-проект изолирован от других контейнеров. Если порт занят, измените
хостовый порт в `app.ports`. Runtime-контейнер работает от непривилегированного пользователя.

```bash
make down
```

Основная БД использует постоянный Docker volume: остановка проекта его не удаляет.
SQL-миграции выполняет отдельный сервис до запуска приложения. На существующей БД
изменение пароля в `.env` не меняет пароль роли автоматически — сохраняйте прежнее
значение или выполняйте ротацию отдельно. Не удаляйте volume для обычной остановки.

## Примеры API

### Подготовка

Примеры выполняются последовательно в одной Bash-сессии. Для доверенного `.env`
с простыми hex-секретами можно явно экспортировать настройки:

```bash
set -a
. ./.env
set +a

API_URL=https://localhost:8443
MD5=$(openssl rand -hex 16)
```

При сложном dotenv-синтаксисе экспортируйте переменные отдельно: синтаксис Compose
и shell не полностью совпадает. Запросы передают API Key через stdin curl и проверяют
сертификат через `--cacert`; отключать проверку с `-k` не требуется.

В JSON-примерах ниже показан условный MD5; команды используют новый случайный хеш.
Системные timestamps приведены для примера и назначаются PostgreSQL.

### Создание записи — POST /info

Тело запроса:

```json
{
  "md5": "d41d8cd98f00b204e9800998ecf8427e",
  "name": "Demo.Initial",
  "description": "Example threat metadata",
  "severity": "high",
  "file_type": "pe",
  "first_seen_at": "2026-11-04T18:00:00Z"
}
```

Запрос с текущим значением `$MD5`:

```bash
POST_BODY=$(cat <<JSON
{
  "md5": "$MD5",
  "name": "Demo.Initial",
  "description": "Example threat metadata",
  "severity": "high",
  "file_type": "pe",
  "first_seen_at": "2026-11-04T18:00:00Z"
}
JSON
)

printf 'X-API-Key: %s\n' "$API_KEY" |
  curl --fail --cacert "$TLS_CERT_FILE" --header @- --include \
    --header 'Content-Type: application/json' --request POST \
    --data "$POST_BODY" "$API_URL/info"
```

Ответ **201 Created**:

```json
{
  "md5": "d41d8cd98f00b204e9800998ecf8427e",
  "name": "Demo.Initial",
  "description": "Example threat metadata",
  "severity": "high",
  "file_type": "pe",
  "first_seen_at": "2026-11-04T18:00:00Z",
  "created_at": "2026-11-05T12:00:00Z",
  "updated_at": "2026-11-05T12:00:00Z"
}
```

Продолжайте обновление только после успешного создания записи. Повторный POST
с тем же MD5 возвращает `409 Conflict`.

### Получение записи — GET /info/{md5}

```bash
printf 'X-API-Key: %s\n' "$API_KEY" |
  curl --fail --cacert "$TLS_CERT_FILE" --header @- --include \
    "$API_URL/info/$MD5"
```

Ответ **200 OK** содержит сохранённые данные:

```json
{
  "md5": "d41d8cd98f00b204e9800998ecf8427e",
  "name": "Demo.Initial",
  "description": "Example threat metadata",
  "severity": "high",
  "file_type": "pe",
  "first_seen_at": "2026-11-04T18:00:00Z",
  "created_at": "2026-11-05T12:00:00Z",
  "updated_at": "2026-11-05T12:00:00Z"
}
```

### Обновление записи — PUT /info/{md5}

PUT полностью заменяет изменяемые поля существующей записи. MD5 задаётся только в URL.

Тело запроса:

```json
{
  "name": "Demo.Updated"
}
```

```bash
printf 'X-API-Key: %s\n' "$API_KEY" |
  curl --fail --cacert "$TLS_CERT_FILE" --header @- --include \
    --header 'Content-Type: application/json' --request PUT \
    --data '{
      "name": "Demo.Updated"
    }' "$API_URL/info/$MD5"
```

Ответ **200 OK**:

```json
{
  "md5": "d41d8cd98f00b204e9800998ecf8427e",
  "name": "Demo.Updated",
  "description": "",
  "severity": "unknown",
  "created_at": "2026-11-05T12:00:00Z",
  "updated_at": "2026-11-05T12:05:00Z"
}
```

Пропущенные поля сбрасываются к defaults:

- `description` становится пустой строкой;
- `severity` становится `unknown`;
- `file_type` и `first_seen_at` становятся неизвестными и отсутствуют в ответе.

`created_at` сохраняется, `updated_at` обновляется. GET после PUT вернёт обновлённые данные.

### Ошибка — 404 Not Found

Если записи нет, GET или PUT возвращает `ErrorResponse`:

```json
{
  "message": "Threat not found"
}
```

Полный сценарий с проверкой статусов можно выполнить после экспорта настроек:

```bash
sh scripts/smoke-https.sh
```

Скрипт использует новый случайный MD5. Тестовая запись остаётся в БД:
операция DELETE не предусмотрена.

## Тестирование

### Unit-тесты

Не требуют PostgreSQL или Docker:

```bash
go test ./...
go vet ./...
```

Проверка гонок данных, при наличии C-компилятора:

```bash
go test -race ./...
```

### Интеграционные тесты в Docker

После настройки `.env`:

```bash
make test-docker
```

Команда выполняет unit-тесты, vet и integration-тесты на отдельной PostgreSQL
в tmpfs. Тестовая сеть и БД изолированы, основной volume не используется.
Проверяются SQL-операции, конкурентное создание записей и реальный HTTPS-сценарий.

Для нативного запуска задайте `TEST_POSTGRES_ADMIN_DSN` с правом CREATEDB:

```bash
go test -tags=integration -count=1 -timeout=2m ./tests/integration
```

Без этой переменной integration-тесты пропускаются. Каждая fixture создаёт
и удаляет собственную случайно именованную БД.

## Документация API

[openapi.yaml](openapi.yaml) — полный контракт OpenAPI 3.0 со схемами, правилами
валидации, аутентификацией и HTTP-ответами. Файл можно импортировать в Swagger UI
или Swagger Editor.

Генерация моделей и маршрутов:

```bash
make generate
make check-generated
```

Версия `oapi-codegen` закреплена в Makefile на **v2.8.1**. Результат —
`internal/delivery/http/generated/api.gen.go`; вручную он не редактируется.
Проверка сравнивает повторную генерацию с существующим файлом и не требует Git.
Генератору может понадобиться доступ к сети.

`.env` и локальные TLS-файлы исключены из Git и Docker build context.
Для проверки Compose используйте `make compose-config` (`config --quiet`):
полный вывод конфигурации может содержать секретные переменные.
