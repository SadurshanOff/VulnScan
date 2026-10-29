# Deploying VulnScan Monitor

This guide takes you from nothing to a live pilot: a small server running the dashboard over HTTPS, the 24/7 worker, and real alerts arriving on your phone and in your inbox. Expect about an hour the first time.

## What you need

- A Linux VPS with 1 GB RAM running Ubuntu 22.04 or 24.04. Hetzner, DigitalOcean, Vultr or Linode all work for about $5 a month.
- A domain or subdomain for the dashboard, for example `monitor.yourcompany.com`.
- A Telegram account, an email account you can send from, and a website you own to test against.

## 1. Prepare the server

Point your dashboard domain at the server: create a DNS **A record** for `monitor.yourcompany.com` with the server's IP address.

Log in over SSH, then install Docker and turn on the firewall:

```bash
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER      # log out and back in after this
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

## 2. Get the code and create your settings

```bash
git clone https://github.com/SadurshanOff/VulnScan.git vulnscan
cd vulnscan
cp .env.example .env
```

Open `.env` in an editor (`nano .env`) and set at least:

| Setting | Value |
| --- | --- |
| `VULNSCAN_SECRET_KEY` | A long random string. Generate one with `openssl rand -hex 32`. |
| `VULNSCAN_ADMIN_PASSWORD` | A strong password for the dashboard. |
| `VULNSCAN_DOMAIN` | Your dashboard domain, for example `monitor.yourcompany.com`. |
| `VULNSCAN_ADMIN_EMAIL` / `VULNSCAN_ADMIN_TELEGRAM_CHAT_ID` | Where you, the analyst, get "review needed" messages. |
| `VULNSCAN_CONTACT_URL` | A page about your service. It appears in the scanner's User-Agent so site hosts know who is checking. |

## 3. Set up Telegram alerts

1. In Telegram, open a chat with **@BotFather**, send `/newbot`, and follow the prompts. Copy the token it gives you into `TELEGRAM_BOT_TOKEN` in `.env`.
2. Open a chat with your new bot and send it any message, for example `/start`. A bot can only message people who have messaged it first, so each client must do this too.
3. Find your chat id:
   ```bash
   curl -s "https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates"
   ```
   Look for `"chat":{"id":123456789` in the output. That number is the chat id you enter for a site in the dashboard.

## 4. Set up email alerts

Any SMTP provider works. Two easy choices:

| Provider | Settings | Notes |
| --- | --- | --- |
| Gmail | `SMTP_HOST=smtp.gmail.com`, `SMTP_PORT=587`, `SMTP_USER` and `SMTP_FROM` = your Gmail address, `SMTP_PASSWORD` = an app password | Turn on 2-step verification, then create an app password at myaccount.google.com/apppasswords. Fine for a pilot (about 500 emails a day). |
| Brevo | `SMTP_HOST=smtp-relay.brevo.com`, `SMTP_PORT=587`, `SMTP_USER` and `SMTP_PASSWORD` from Brevo's SMTP settings page | Free tier sends 300 emails a day. Verify your sending domain for better delivery. |

For a business you sell to clients, send from your own domain and set up its SPF and DKIM records as your provider explains, so alerts do not land in spam.

## 5. Start everything

```bash
docker compose --profile https up -d --build
```

This starts three containers: the dashboard, the 24/7 worker, and Caddy, which gets a free HTTPS certificate for your domain automatically. Check that they are running:

```bash
docker compose --profile https ps
docker compose logs -f worker      # Ctrl+C to stop following
```

## 6. Send yourself a test alert

```bash
docker compose run --rm worker python -m monitor.notify --email you@example.com --telegram 123456789
```

Each channel prints `sent to ...` or `FAILED (...)` with the reason. Fix `.env`, then run `docker compose --profile https up -d` again to reload the settings, and repeat until both work.

## 7. Run a pilot on your own site

1. Open `https://monitor.yourcompany.com`, log in, and go to **Monitored sites**.
2. Add your own website with your email and Telegram chat id, then record an authorisation for it (for your own site, reference something like "own site").
3. On the site's page, copy the verification token. Create a file at `https://yoursite.com/.well-known/vulnscan-verify.txt` containing only that token. On most hosts, that means creating a `.well-known` folder in the web root.
4. Click **Verify**, then **Scan now / retest**. You get a "review needed" message within a minute.
5. On the site page, approve the findings, then click **Send approved findings to the client**. The client alert arrives.
6. Fix one finding, for example add a missing header, then click **Scan now / retest** again. You should get a "fixed" message.
7. Open **Client report** and save it as PDF.

From then on, the worker scans the site every 6 hours by itself.

## Onboarding a paying client

1. Get signed written authorisation covering scope, frequency, contact details, and whether active tests are allowed. Record it on the site page.
2. Ask them to message your Telegram bot and send you their chat id, or just use their email.
3. Add the site, send them the verification instructions from step 7, and click **Verify** once they have done it.

## Keeping it running

**Update to a new version:**

```bash
cd vulnscan && git pull && docker compose --profile https up -d --build
```

**Back up the database** (all sites, findings and history). Run this daily from cron, and copy the file off the server:

```bash
docker compose stop worker
docker run --rm -v vulnscan_data:/data -v "$PWD":/backup alpine tar czf /backup/vulnscan-$(date +%F).tgz /data
docker compose start worker
```

The volume is named after the folder you cloned into. Run `docker volume ls` if `vulnscan_data` is not found.

**Security basics:**
- Keep `.env` private. It holds your passwords and bot token.
- Use SSH keys and turn off password login for SSH.
- Turn on unattended security updates: `sudo apt install unattended-upgrades`.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| Browser shows a certificate error on the dashboard | Check that the DNS A record points at the server and that ports 80 and 443 are open, then run `docker compose logs caddy`. |
| Login fails or the page says "Invalid or missing CSRF token" | Set `VULNSCAN_SECRET_KEY` in `.env` and restart. |
| "Verification file not found" | Open the verification URL in a browser. It must return only the token, with no redirect and no HTML. |
| "resolves to a private or internal address" | The site points at a private IP. Monitoring is only for public sites. |
| No alerts arrive | Run the test alert from step 6 and read the error. |
