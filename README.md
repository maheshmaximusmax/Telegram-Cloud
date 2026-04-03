# 🔐 TeleVault — Encrypted Cloud Storage via Telegram

**Free, unlimited, end-to-end encrypted cloud storage** that uses Telegram as the storage backend. No server needed. Your files are encrypted in your browser before they ever leave your device.

![Status](https://img.shields.io/badge/Status-Ready-green) ![Encryption](https://img.shields.io/badge/Encryption-AES--256--GCM-blue) ![Storage](https://img.shields.io/badge/Storage-Telegram-blue)

---

## ⚡ How It Works

```
Your File → AES-256 Encrypt (in browser) → Upload to Telegram → Store metadata on GitHub
                                ↓
                    Only YOU have the password
                    Even Telegram can't read your files
```

1. **You set a master password** → it derives an encryption key (PBKDF2, 100k iterations)
2. **Upload any file** → encrypted with AES-256-GCM entirely in your browser
3. **Encrypted blob** → sent to your Telegram channel/chat (free, unlimited storage)
4. **Metadata** (filename, file_id, IV) → stored on GitHub for multi-device access
5. **Download** → fetches from Telegram → decrypts in browser → saves to your device

**Zero knowledge**: Your password never leaves your browser. No server, no backend.

---

## 🚀 Quick Start (5 minutes)

### Step 1: Create a Telegram Bot

1. Open Telegram and search for **@BotFather**
2. Send `/newbot` and follow the prompts
3. Copy the **Bot Token** (looks like `123456:ABCdefGhIjKlMnOpQrStUvWxYz`)

### Step 2: Create a Storage Channel

1. In Telegram, create a **New Private Channel** (e.g., "My Cloud Storage")
2. Go to Channel Settings → **Administrators** → **Add Admin** → search your bot name → add it
3. Give it **Post Messages** permission
4. To get the Channel ID: Forward any message from the channel to **@userinfobot** — it will reply with the channel ID (starts with `-100`)

> **Alternative**: You can also use your own Telegram user ID as the chat ID. Send `/start` to your bot, then visit `https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates` to find your chat ID.

### Step 3: Deploy TeleVault

#### Option A: GitHub Pages (Recommended — access from anywhere via link)

1. **Create a new GitHub repository** (e.g., `televault`)
2. Upload `index.html` and `app.js` to the repo
3. Go to **Settings → Pages → Source: Deploy from branch → Branch: main → Save**
4. Your vault is now live at: `https://yourusername.github.io/televault/`

#### Option B: Open Locally

Just double-click `index.html` — it works offline (except for upload/download which needs internet).

### Step 4: Set Up Your Vault

1. Open TeleVault (via link or locally)
2. **Create a Master Password** (minimum 8 characters — YOU MUST REMEMBER THIS)
3. Enter your **Bot Token** and **Channel ID**
4. (Optional) Add GitHub credentials for multi-device sync
5. Done! Start uploading files 🎉

---

## 📁 Features

| Feature | Description |
|---------|-------------|
| 🔐 **E2E Encryption** | AES-256-GCM + PBKDF2 key derivation, entirely in-browser |
| ☁️ **Unlimited Storage** | Telegram provides free, unlimited file storage |
| 📁 **Folder Management** | Create folders, move files, organize like a file manager |
| 🖼️ **File Preview** | Preview images and text files directly in the browser |
| 🔍 **Search & Sort** | Find files by name, sort by date/size/name |
| 📱 **Mobile Friendly** | Responsive design works on phones and tablets |
| 🌙 **Dark/Light Theme** | Premium UI with both themes |
| 📦 **Large File Support** | Files split into 19MB chunks (auto-chunking) |
| 🔄 **GitHub Sync** | Metadata synced to GitHub for multi-device access |
| 🖱️ **Drag & Drop** | Drop files anywhere on the page to upload |
| 📋 **Grid/List View** | Switch between grid and list views |
| ⌨️ **Keyboard Shortcuts** | Ctrl+U to upload, Del to delete, Esc to close |

---

## 🔒 Security

- **Encryption**: AES-256-GCM (military-grade symmetric encryption)
- **Key Derivation**: PBKDF2 with 100,000 iterations and SHA-256
- **Random Salt**: 32 bytes, unique per vault
- **Random IV**: 12 bytes, unique per file
- **Zero Knowledge**: Password never stored or transmitted
- **Client-Side Only**: All encryption/decryption happens in your browser
- **Verifier**: Password correctness verified using encrypted known-string (not hash)

> ⚠️ **WARNING**: If you lose your master password, your files are **permanently unrecoverable**. There is no "forgot password" option — that's the point of E2E encryption.

---

## 📱 Access From Anywhere

Once deployed on GitHub Pages, access your vault from any device:

```
https://yourusername.github.io/televault/
```

- Open on your phone, laptop, tablet — anywhere
- Enter your master password to unlock
- Metadata auto-syncs from GitHub
- Files download from Telegram on demand

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────┐
│           YOUR BROWSER                  │
│  ┌─────────────────────────────────┐    │
│  │  Password → PBKDF2 → AES Key   │    │
│  │  File → AES-256-GCM Encrypt    │    │
│  │  Encrypted → Chunk (19MB each) │    │
│  └──────────┬──────────────────────┘    │
│             │                           │
└─────────────┼───────────────────────────┘
              │
    ┌─────────┴─────────┐
    ▼                   ▼
┌────────┐        ┌──────────┐
│Telegram│        │  GitHub  │
│(Files) │        │(Metadata)│
│Free ∞  │        │  JSON    │
└────────┘        └──────────┘
```

---

## ⚙️ Limits

| Limit | Value | Workaround |
|-------|-------|------------|
| Max file upload | 50 MB per chunk | Files auto-split into 19MB chunks |
| Max file download | 20 MB per chunk | Chunk size is 19MB, under limit |
| Max total per file | ~2 GB | 100+ chunks × 19MB |
| GitHub repo size | 1 GB (free) | Only stores ~1KB metadata per file |
| Telegram storage | Unlimited | Free forever |

---

## 🛠️ Troubleshooting

**"Upload failed"**
- Check your Bot Token and Chat ID in Settings
- Make sure the bot is added as admin to the channel
- Check internet connection

**"Download failed"**
- File chunks from Telegram may have expired (very rare, Telegram keeps files indefinitely)
- Try re-downloading

**"GitHub sync failed"**
- Check your GitHub PAT has `repo` scope
- Make sure the repository exists
- Token may have expired — generate a new one

**Can't access from another device**
- Make sure GitHub sync is configured
- Use the same master password on all devices
- Open the same GitHub Pages URL

---

## 📄 License

MIT — Free to use, modify, and distribute.

---

**Made with 🔐 by TeleVault** — Your files, your keys, your privacy.
