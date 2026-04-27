# ModSafe Launch Checklist

## Day 1: Security Baseline
- Set production `.env` values from `.env.example`.
- Generate a long `SESSION_SECRET`.
- Generate a different long `API_KEY_PEPPER`.
- Set `CORS_ORIGIN` to the exact production domain.
- Set `ADMIN_PASSWORD_HASH` with `npm run hash:admin -- "YourLongAdminPassword1!"`.
- Confirm `/admin.html` requires backend login.
- Confirm security headers are present on `/health` and `/admin.html`.

## Day 2: Database and Deploy
- Create a production PostgreSQL database.
- Set `DATABASE_URL` on the hosting platform.
- Run the app once and confirm the tables are created.
- Visit `/health` and confirm it returns `{ "ok": true }`.

## Day 3: Core User Flow
- Register a new user.
- Log in and copy the API key.
- Rotate the API key once and confirm the old key no longer works.
- Call `/moderate` with the API key.
- Confirm usage increments.
- Confirm dashboard logs appear.

## Day 4: Moderation Quality
- Test safe, abusive, spam, Hinglish, and custom banned-word examples.
- Check false positives and false negatives.
- Tune the word lists and OpenRouter threshold if needed.

## Day 5: Admin and Monitoring
- Log into `/admin.html`.
- Confirm users and logs load from production data.
- Check `combined.log` and `error.log`.
- Confirm failed admin login does not reveal credentials.

## Day 6: Legal and Product Pages
- Review pricing, privacy, terms, refund, and about pages.
- Add real contact/support details.
- Confirm landing page CTA opens auth.

## Day 7: Launch Rehearsal
- Run `npm test`.
- Run `node --check server.js`.
- Smoke test register, login, dashboard, `/moderate`, `/test-moderate`, and admin.
- Back up the production database.
- Launch as beta.
