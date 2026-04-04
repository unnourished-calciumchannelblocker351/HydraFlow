<p align="center">
  <img src="docs/assets/hydraflow-logo.svg" alt="HydraFlow" width="120"/>
</p>
<h1 align="center">HydraFlow</h1>

<p align="center">
  <strong>Обход блокировок интернета. Работает в России, Китае, Иране и других странах.</strong>
</p>

<p align="center">
  <a href="https://github.com/Evr1kys/HydraFlow/releases"><img src="https://img.shields.io/github/v/release/Evr1kys/HydraFlow?style=flat-square" alt="Release"></a>
  <a href="https://github.com/Evr1kys/HydraFlow/actions"><img src="https://img.shields.io/github/actions/workflow/status/Evr1kys/HydraFlow/ci.yml?style=flat-square" alt="CI"></a>
  <a href="https://github.com/Evr1kys/HydraFlow/blob/main/LICENSE"><img src="https://img.shields.io/github/license/Evr1kys/HydraFlow?style=flat-square" alt="License"></a>
  <a href="https://goreportcard.com/report/github.com/Evr1kys/HydraFlow"><img src="https://goreportcard.com/badge/github.com/Evr1kys/HydraFlow?style=flat-square" alt="Go Report"></a>
</p>

<p align="center">
  <a href="README.md">English</a> &bull;
  <b>Русский</b> &bull;
  <a href="README.zh.md">中文</a>
</p>

---

## Что это такое?

HydraFlow -- инструмент для обхода блокировок интернета.

Вы ставите его на сервер (VPS) за пределами страны с блокировками, и он:
- Настраивает **несколько способов обхода одновременно**
- Автоматически определяет вашего провайдера
- Даёт вам **лучший способ подключения** именно для вашей сети
- Если один способ заблокировали -- **переключается на другой сам**

Работает с обычными приложениями: v2rayNG, Hiddify, Clash, sing-box.

---

## Установка (30 секунд)

Нужен VPS (сервер) за пределами страны с блокировками. Подойдёт любой дешёвый VPS с Debian, Ubuntu или CentOS.

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Evr1kys/HydraFlow/main/install.sh)
```

После установки вы получите:
- **Ссылку** для v2rayNG -- скопировать и вставить
- **URL подписки** -- добавить в любое приложение, конфиги обновляются сами
- **QR-код** -- отсканировать телефоном

Всё. Теперь подключаем устройства.

---

## Подключение

### Android
1. Скачайте [v2rayNG](https://play.google.com/store/apps/details?id=com.v2ray.ang) из Google Play (или с [GitHub](https://github.com/2dust/v2rayNG/releases))
2. Нажмите **+** > **Импорт из буфера обмена** > вставьте ссылку
3. Нажмите кнопку подключения

### iPhone
1. Скачайте [Hiddify](https://apps.apple.com/app/hiddify-proxy-vpn/id6596777532) (бесплатно) или [Streisand](https://apps.apple.com/app/streisand/id6450534064) из App Store
2. **Добавить профиль** > вставьте URL подписки
3. Подключитесь

### Windows
1. Скачайте [Hiddify](https://github.com/hiddify/hiddify-app/releases) или [v2rayN](https://github.com/2dust/v2rayN/releases)
2. Добавьте URL подписки
3. Подключитесь

### macOS
1. Скачайте [Hiddify](https://github.com/hiddify/hiddify-app/releases) или [Clash Verge Rev](https://github.com/clash-verge-rev/clash-verge-rev/releases)
2. Добавьте URL подписки
3. Подключитесь

### Linux
1. Скачайте [Hiddify](https://github.com/hiddify/hiddify-app/releases) или [nekoray](https://github.com/MatsuriDayo/nekoray/releases)
2. Добавьте URL подписки
3. Подключитесь

---

## Как это работает?

HydraFlow настраивает все известные способы обхода одновременно:

| Способ | Что делает | Когда помогает |
|--------|-----------|----------------|
| **Reality** | Маскирует ваш трафик под обычный HTTPS (как будто вы заходите на microsoft.com) | Основной способ, работает почти везде |
| **WebSocket + CDN** | Пропускает трафик через Cloudflare | Когда прямой доступ к серверу заблокирован по IP |
| **Hysteria2** | Быстрый шифрованный тоннель через QUIC (UDP) | Когда нужна максимальная скорость |
| **ShadowTLS** | Настоящий TLS-хэндшейк, устойчивый к активным проверкам | Когда блокировщики активно проверяют подозрительные серверы |
| **Shadowsocks-2022** | Шифрованный тоннель без TLS | Альтернатива когда VLESS заблокирован |
| **Chain (цепочка)** | Трафик идёт через промежуточный сервер | Когда блокируют все зарубежные IP |
| **Фрагментация** | Разбивает пакеты на мелкие части | Обходит DPI, который не собирает фрагменты обратно |

### Умная подписка -- главная фишка

Когда ваше приложение (v2rayNG / Hiddify) обновляет подписку, HydraFlow:
1. Определяет вашего провайдера (МегаФон, МТС, Билайн, Ростелеком...)
2. Проверяет какие способы сейчас работают у вашего провайдера
3. Отдаёт вам конфигурацию **только с рабочими способами**, отсортированными по скорости

Если завтра блокировщики закроют какой-то способ -- при следующем обновлении подписки он исчезнет, а вместо него появятся рабочие альтернативы.

---

## Настройка CDN (когда прямой доступ заблокирован)

Если IP вашего сервера заблокировали, можно пустить трафик через Cloudflare CDN. Заблокировать это очень сложно -- ваш трафик смешивается с миллионами других сайтов.

[Подробная инструкция](docs/cdn-setup.md)

Коротко:
1. Купите домен (~$1 за .xyz)
2. Добавьте его в [Cloudflare](https://dash.cloudflare.com/) (бесплатный тариф)
3. Направьте домен на IP сервера (оранжевое облачко включено)
4. Выполните на сервере:
   ```bash
   hydraflow cdn --domain your-domain.com
   ```

Теперь даже если IP заблокирован -- путь через CDN работает.

---

## Использование с 3x-ui или Marzban

Если у вас уже стоит 3x-ui или Marzban, HydraFlow работает рядом с ними. Он читает их данные и добавляет умные подписки поверх:

```bash
# С 3x-ui
bash <(curl -fsSL https://raw.githubusercontent.com/Evr1kys/HydraFlow/main/install.sh) --mode 3xui

# С Marzban
bash <(curl -fsSL https://raw.githubusercontent.com/Evr1kys/HydraFlow/main/install.sh) --mode marzban
```

Ваши существующие пользователи получат умные подписки автоматически -- ничего переносить не нужно.

---

## Несколько серверов

Если один сервер заблокировали -- клиенты автоматически переключатся на другой.

[Подробная инструкция](docs/multi-server.md)

```bash
# На основном сервере добавьте второй:
hydraflow server add 1.2.3.4 my-secret-key

# Проверить все серверы:
hydraflow server health
```

---

## Управление сервером

```bash
hydraflow user add friend@mail.ru    # Добавить пользователя
hydraflow user sub friend@mail.ru    # Получить его ссылку подписки
hydraflow user list                  # Список всех пользователей
hydraflow user del friend@mail.ru    # Удалить пользователя

hydraflow status                     # Статус сервера
hydraflow server health              # Проверить все серверы
hydraflow probe server.com:443       # Проверить наличие блокировок

# Или через systemd:
systemctl status hydraflow           # Статус сервиса
journalctl -u hydraflow -f           # Посмотреть логи
```

Docker:

```bash
docker run -d --name hydraflow --network host \
  -v /etc/hydraflow:/etc/hydraflow \
  ghcr.io/evr1kys/hydraflow:latest
```

---

## Сравнение с аналогами

| Возможность | HydraFlow | Xray | sing-box | Amnezia | Outline |
|-------------|-----------|------|----------|---------|---------|
| Установка одной командой | Да | Нет | Нет | Да | Да |
| Автовыбор рабочего способа | Да | Нет | Нет | Нет | Нет |
| Работает при блокировке IP (CDN) | Да | Вручную | Вручную | Нет | Нет |
| Умная подписка по провайдеру | Да | Нет | Нет | Нет | Нет |
| Несколько серверов с переключением | Да | Нет | Частично | Нет | Нет |
| Несколько способов обхода | Да | Да | Да | Частично | Нет |

---

## Решение проблем

Не подключается? [Подробный гайд по решению проблем](docs/troubleshooting.md)

Быстрая проверка:
- Убедитесь что сервер работает: `hydraflow status`
- Проверьте доступность портов: `hydraflow probe ваш-сервер:443`
- Попробуйте обновить подписку в приложении
- Если ничего не работает напрямую -- настройте CDN (см. выше)

---

## Безопасность и приватность

- Нулевое логирование -- ваш трафик и посещаемые сайты нигде не записываются
- Ссылки подписки защищены криптографическими токенами
- Анонимная телеметрия: только имя провайдера + какой способ работает, без IP-адресов
- Все проверки блокировок выполняются локально на вашем устройстве

Подробнее в [SECURITY.md](SECURITY.md).

---

## Для разработчиков

<details>
<summary>Архитектура, сборка из исходников и участие в разработке</summary>

### Структура проекта

```
cmd/
  hydraflow/       CLI-инструмент (команды user, server, status, probe)
  hf-server/       Серверный бинарник
  hydraflow-panel/ Веб-панель
smartsub/          Движок умных подписок (определение провайдера, скоринг протоколов)
bypass/            Движок обхода (фрагментация, паддинг, десинхронизация, цепочки)
discovery/         Обнаружение блокировок (пробы, фингерпринтинг, карта блокировок)
protocols/         Реализации протоколов
  reality/         VLESS + Reality
  xhttp/           VLESS + XHTTP (работает через CDN)
  hysteria2/       Hysteria2 (QUIC)
  shadowtls/       ShadowTLS v3
  chain/           Цепочки прокси (multi-hop)
  hydra/           Нативный протокол HydraFlow
subscription/      Генерация подписок (форматы V2Ray, Clash, sing-box)
integrations/      Адаптеры для 3x-ui и Marzban
server/            Установщик сервера и поиск SNI
config/            Управление конфигурацией
```

### Ключевые компоненты

- **Умные подписки** (`smartsub/`) -- Главное отличие от аналогов. Определяет провайдера, оценивает протоколы по проценту успеха, выдаёт конфиги во всех форматах. [Спецификация формата подписки](docs/subscription-format.md)
- **Движок обхода** (`bypass/`) -- Фрагментация, паддинг, десинхронизация, DNS-трюки. [Документация по методам обхода](docs/bypass-methods.md)
- **Обнаружение блокировок** (`discovery/`) -- Зондирование, TLS-фингерпринтинг, агрегация карты блокировок. [Документация probe engine](docs/probe-engine.md)
- **Выбор протокола** -- Взвешенный скоринг: `score = probe * 0.5 + history * 0.3 + priority * 0.2`. [Документация архитектуры](docs/architecture.md)

### Сборка из исходников

```bash
git clone https://github.com/Evr1kys/HydraFlow.git
cd HydraFlow
make build-all    # Собирает hydraflow, hf-server, hydraflow-sub
make test         # Запуск тестов
make lint         # Запуск линтера
```

### API

Межсерверное взаимодействие через gRPC. Proto-определения в `api/proto/`.

### Участие в разработке

Смотрите [CONTRIBUTING.md](CONTRIBUTING.md).

</details>

---

## Лицензия

[MPL-2.0](LICENSE) -- свободное использование, модификации кода HydraFlow должны оставаться открытыми.

## Благодарности

Построен на основе работ [Xray-core](https://github.com/XTLS/Xray-core), [Hysteria](https://github.com/apernet/hysteria), [ShadowTLS](https://github.com/ihciah/shadow-tls), [AmneziaVPN](https://github.com/amnezia-vpn), а также пионеров обхода DPI -- [GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI) и [zapret](https://github.com/bol-van/zapret).

---

<p align="center">
  <em>"Отрубишь одну голову -- вырастут две новые."</em>
</p>
