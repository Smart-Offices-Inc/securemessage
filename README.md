# SecureMessages :lock: :rocket: :clipboard:

_A secure message sharing platform built with Go, Echo, GORM, AES encryption, ephemeral CSRF, and dynamic CSP!_ :sparkles:

:globe-with-meridians: [https://sms.smartservices.tech](sms.smartservices.tech)

---

## Table of Contents  :file_folder:
- [SecureMessages :lock: :rocket: :clipboard:](#securemessages-lock-rocket-clipboard)
  - [Table of Contents  :file\_folder:](#table-of-contents--file_folder)
  - [Introduction :wave:](#introduction-wave)
  - [Features :star:](#features-star)
  - [Requirements :gear:](#requirements-gear)
  - [Installation :wrench:](#installation-wrench)
    - [Clone the Repo](#clone-the-repo)
    - [Build via Go](#build-via-go)
    - [Or Docker](#or-docker)
  - [Configuration :gear:](#configuration-gear)
  - [Usage :computer:](#usage-computer)
  - [Log Rotation \& Crash Recovery :arrows\_clockwise:](#log-rotation--crash-recovery-arrows_clockwise)
  - [Security Notes :lock:](#security-notes-lock)
  - [Contributing :handshake:](#contributing-handshake)
  - [License :page\_facing\_up:](#license-page_facing_up)

---

## Introduction :wave:

**SecureMessages** is an encrypted secret-sharing application. It leverages:
- **Go | Echo** for robust web serving
- **GORM** with SQLite for storing ephemeral messages
- **AES** encryption with optional password protection
- **View Once** messages that self-destruct after a single view
- **CSRF** ephemeral tokens & **nonce-based** CSP for advanced security
- **Bootstrap** for clean, responsive UI :sparkling_heart:

**Use Cases**:
- Share sensitive data (passwords, tokens) once and destroy
- Automate ephemeral secure messages behind a single-page form

---

## Features :star:

- **Ephemeral CSRF**: Each instance auto-generates a CSRF secret
- **Nonce-based CSP**: Dynamically sets `Content-Security-Policy` with script/style nonces
- **Encrypted Storage**: Database only holds AES-encrypted message content
- **One-Time View**: Mark a message as “view once” to destroy upon first view
- **Admin Panel**: BasicAuth-protected interface to list/delete messages
- **Automatic Cleanup**: Cron-like goroutines that purge expired or viewed messages
- **Bootstrapped UI**: Responsive, includes copy-to-clipboard and optional password protection
- **Dockerizable**: Perfect for container deployments; works behind Traefik for SSL termination

---

## Requirements :gear:

- **Go >= 1.18**  
- **Docker** (optional, for container builds)
- **SQLite** (built-in DB engine, no extra install needed)
- **Traefik** or another reverse proxy (for SSL termination, if desired)

---

## Installation :wrench:

### Clone the Repo
```bash
git clone https://github.com/Smart-Offices-Inc/securemessages.git
cd SecureMessages
```

### Build via Go
```bash
go build -o securemessages ./cmd/securemessages
./securemessages
```

### Or Docker
```bash
docker build -t securemessages:latest .
docker run -d -p 9203:9203 --name securemessages securemessages:latest
```

---

## Configuration :gear:

**Environment Variables / config.yml**:
- `ENV`: `development` or `production`
- `PORT`: The port to run on (default 9203)
- `DB_PATH`: Path to SQLite database file
- `AES_KEY`: Base64-encoded 32-byte AES key
- `MASTER_KEY`: Base64-encoded 32-byte master key
- `CSRF_AUTH_KEY`: Base64-encoded 32-byte CSRF key (for ephemeral override)
- `ADMIN_USERNAME`, `ADMIN_PASSWORD`: BasicAuth credentials for `/admin`

**By default**, the app writes these keys into `./config/config.yml` if they aren’t set as environment variables.

---

## Usage :computer:

**1. Create a Message**  
   - Visit the root path `/` in a browser to see the creation form
   - Fill out your message, set expiration, enable password (optional), and choose “view once” (optional)
   - Submit to get a **share link** to the message

**2. Share Link**  
   - Copy the generated link and provide it to the recipient
   - If password-protected, they must supply the correct password
   - If marked “view once,” the message is deleted immediately after viewing

**3. Admin Panel**  
   - BasicAuth-protected under `/admin`
   - View paginated messages (encrypted content shown as `[Encrypted]`)
   - Delete single messages or delete all
   - Regenerate AES or CSRF keys (re-encryption logic might also run here)

---

## Log Rotation & Crash Recovery :arrows_clockwise:

**Log Rotation**  
Best handled by Docker’s built-in logging driver or external solutions. For example, in your `docker-compose.yml`:
```yaml
logging:
  driver: "json-file"
  options:
    max-size: "10m"
    max-file: "3"
```

**Crash Recovery**  
Use Docker **restart policies** (e.g. `restart: unless-stopped`) so the container auto-restarts if the app crashes.

---

## Security Notes :lock:

1. **Traefik** handles SSL termination externally. Internally, the app sees HTTP on port 9203.  
2. **CSRF** ephemeral tokens + **nonce-based CSP** protect from XSS & CSRF attacks.  
3. **AES** encryption ensures messages are stored encrypted at rest in SQLite.  
4. **Password Option**: Additional layer if message content is sensitive; hashed via bcrypt.  
5. **View Once** messages are destroyed upon viewing, reinforcing ephemeral data handling.

---

## Contributing :handshake:

1. Fork & clone the repo  
2. Create feature branches  
3. Submit PRs describing changes  
4. Ensure lint & tests pass  
5. If large changes, open an issue first

---

## License :page_facing_up:

This project is released under the **GPL v3.0**. See `LICENSE` file for details. :sparkling_heart:

**Happy Sharing!** :smiley:
