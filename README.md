# 🚀 Deployment Guide

Deploy this app to **Render** or **Railway** in minutes. Both platforms auto-detect HTTP port binding from `$PORT`, so there's no "open a port" step like on a VPS — you just need your app listening on `0.0.0.0:$PORT`, which `main.py` / `Procfile` already handle.

---

## 📋 Quick Comparison

| | Render (Free) | Railway (Free) |
|---|---|---|
| **Config source** | `render.yaml` (Blueprint) | `Procfile` |
| **Auto domain** | ✅ Instant on first deploy | ❌ Manual click required |
| **Persistent storage** | ❌ Not on Free tier | ✅ Volumes supported |
| **Idle behavior** | 💤 Sleeps after 15 min | 🏃 Stays awake, but limited credit |
| **Setup effort** | Lowest (Blueprint auto-fills) | Low (Procfile auto-detected) |

---

## 🟣 Render

### 1. Create the Service

Push the project to a GitHub repo (public or private — both work).

**Option A — Blueprint (recommended)**

> Render dashboard → **New → Blueprint** → connect the repo

Because `render.yaml` lives in the repo root, Render reads it and pre-fills everything — free plan, Frankfurt region, build/start commands. Just confirm.

**Option B — Manual setup**

> **New → Web Service** → connect repo

| Setting | Value |
|---|---|
| Build Command | `pip install -r requirements.txt` |
| Start Command | `uvicorn main:app --host 0.0.0.0 --port $PORT` |
| Instance Type | Free |

### 2. Environment Variables

In the service's **Environment** tab (or during Blueprint setup):

```
ADMIN_PASSWORD = <your desired first login password>
```

> ⚠️ `PORT` is injected automatically by Render — don't set it yourself.

### 3. Persistent Disk / Volume

> **Not possible on Free.** Per Render's current docs, persistent disks can only attach to a **paid** web service, private service, or background worker.

On Free, `panel.db` lives on ephemeral storage — it survives restarts but is **wiped on every redeploy**.

**Practical effect:** recreate your links after each redeploy, or upgrade to **Starter (~$7/mo)** if that's a dealbreaker.

### 4. Domain

Render assigns `https://<service-name>.onrender.com` automatically the moment the first deploy succeeds — nothing to click. Add a custom domain later under **Settings → Custom Domains** (automatic TLS included).

### 5. Ports

Nothing to open manually. Render terminates TLS at its edge and forwards to whatever port your process binds via `$PORT`.

### 💤 Quirk to Know

Free services **spin down after 15 minutes idle** and take a few seconds to wake on the next request — this is exactly what the app's built-in keep-alive ping is fighting, though Render may still spin it down during low-traffic windows regardless.

---

## ⚫ Railway

### 1. Create the Project

> Railway → **New Project → Deploy from GitHub repo** → pick the repo

Railway reads the `Procfile` automatically — no build/start command fields to fill in manually. (Override later under **Settings → Deploy** if needed.)

### 2. Environment Variables

> Service → **Variables** tab

```
ADMIN_PASSWORD = <your desired first login password>
```

`PORT` is injected by Railway automatically — your app binds to `0.0.0.0:$PORT`, which it already does.

### 3. Persistent Disk / Volume

Railway **does** support volumes (unlike Render's free tier) — but check the economics first:

> As of current signup terms: the trial month gives **$5 of credit**; afterwards you drop to a free tier with **$1 of credit/month**. That's thin, and a volume adds to your usage draw.

**To attach one:**

1. Service → **Settings → Volumes → New Volume**
2. Set a mount path, e.g. `/data`
3. Set env var `DB_PATH=/data/panel.db`

The app already reads `DB_PATH` — no code change needed. SQLite will now write to the persistent volume instead of the ephemeral container filesystem.

> If you skip the volume: behavior matches Render Free — DB resets on redeploy, survives plain restarts.

### 4. Domain

Not automatic here:

> Service → **Settings → Networking → Generate Domain**

You'll get something like `your-app-production.up.railway.app`, TLS included.

### 5. Ports

Same as Render — nothing to open manually. Railway's edge proxies to your `$PORT`.

### ⚡ Quirk to Know

Railway doesn't sleep idle free services the way Render does — but it also doesn't give unlimited runway. That **$1/mo credit** on the free tier is small: a single low-traffic personal tunnel is realistic, but watch the usage dashboard.

---

## 🧭 Which Should You Pick?

- **Want zero-maintenance and don't mind losing DB data on redeploy?** → **Render Free**
- **Need your SQLite data to survive redeploys and can tolerate a tight credit budget?** → **Railway + Volume**
- **Running something low-traffic and personal?** → Either works; Render sleeps, Railway meters credit.

---

<sub>Both platforms handle TLS and port forwarding for you — the only real decisions are around persistence and idle behavior.</sub>
