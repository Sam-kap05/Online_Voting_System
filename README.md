# DeshGarv - Secure Online Voting Portal

Web-based voting portal: **Aadhaar + SMS OTP + live face match**, voter **self-registration**,
tamper-evident ballot ledger, and an accessibility suite (text-to-speech, font scaling,
high contrast, translation). Built with Flask, SQLite and DeepFace.

## Voter flow (every step is enforced on the server)

1. **Register** (`/register`): details -> face photo (upload or camera) -> OTP sent to your mobile -> registered.
2. **Vote** (`/verify`): Aadhaar -> OTP -> live webcam face match (3 consecutive matches, exactly one face) -> **liveness check (follow 3 random head-turn prompts)** -> ballot -> receipt.

## Setup (Windows / macOS / Linux)

Python 3.10-3.12 recommended. First run downloads ~580 MB of VGG-Face weights.

```
python -m venv venv
venv\Scripts\activate          # macOS/Linux: source venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000 (the browser camera works on `localhost` or HTTPS only).

> If you previously installed `opencv-python` 5.x, run `pip install "opencv-python>=4.9,<5"`:
> 5.x has no Haar cascade files and face detection fails.

## Demo mode (default)

Prints/shows OTPs on screen and uses the demo admin login `admin` / `admin123`. Demo data:

| Scenario | Aadhaar | Expected |
|---|---|---|
| A. Normal voter (Samarth Kapoor, New Delhi) | `123456789012` | OTP -> face match against `demo_data/reference.jpg` -> vote |
| B. Already voted | `444455556666` | "This citizen has already cast their vote." |
| C. Two faces in frame | log in as A | status "ONLY 1 PERSON ALLOWED IN FRAME", ballot stays locked |
| D. Results | `/admin` -> `/results` | charts + hash-chained ledger status (admin only) |
| E. Self-register | `/register` | any unused 12-digit Aadhaar, 10-digit mobile starting 6-9, a clear face photo |

## Tests

```
pytest tests/test_app.py                # fast, fake face engine
python tests/test_liveness.py         # (included above) liveness logic + attack scenarios
python tests/e2e_real_face.py           # real DeepFace pipeline
# tests/test_firebase.py (in the pytest run) covers Firebase token verification and flows
python tests/e2e_real_liveness.py       # real RetinaFace: photo / tilted-photo attacks
python tests/e2e_real_kyc.py            # real face models + signed UIDAI-style files (set E2E_OTHER_PERSON_PHOTO for the impostor test)
python tests/liveness_probe.py          # calibrate head-turn thresholds on your webcam
```

## Aadhaar verification (UIDAI offline e-KYC) and one-person-one-registration

**The problem:** typing an Aadhaar number proves nothing - anyone who knows a number could register as that person.
**What this adds:** every voter uploads the *Paperless Offline e-KYC* ZIP that UIDAI itself issues. Only the Aadhaar holder can
download it (UIDAI's site asks for the Aadhaar number/VID **and an OTP sent to the Aadhaar-linked mobile**), and UIDAI signs it,
so anyone can verify it with UIDAI's public certificate - **no UIDAI licence or API access is needed** (real-time Aadhaar
authentication, by contrast, needs a licensed AUA/KUA, which an individual cannot get).

What the server checks on `/register`:

| Check | Stops |
|---|---|
| UIDAI's digital signature (RSA-SHA256), file < 3 days old | forged or edited files, old leaked files |
| the last 4 digits in the file = the Aadhaar number typed | using someone else's file |
| the typed mobile = the Aadhaar-linked mobile (hash recipe from UIDAI's spec) | the OTP going to a phone the holder doesn't control |
| age from the signed date of birth >= `MIN_VOTING_AGE` | under-age registration |
| selfie matches the UIDAI-signed photo | the right file with the wrong face |
| one identity per (name, date of birth, gender, last 4) | the same person registering twice, however many numbers/phones/photos |
| the voter's **name comes from the file** | made-up names |

The file, the share code and the UIDAI photo are read in memory and **never stored** (UIDAI's terms forbid sharing them).

**Setup:** download UIDAI's public certificate from https://uidai.gov.in/en/aadhaar-paperless-offline-e-kyc ("Get Certificate")
and save it in `uidai_certs/` (see `uidai_certs/README.txt`). With `AADHAAR_KYC=offline_xml` (the default in production) the app
refuses to start without it; `AADHAAR_KYC=off` skips the whole check (demo only).

**What voters do:** download the ZIP at myaadhaar.uidai.gov.in (Offline e-KYC, choose a share code), upload it with the share
code, and use their Aadhaar-linked mobile. The registration page explains this.

**The selfie-vs-UIDAI-photo match is a *soft* check.** UIDAI's own documentation says the photo is a *low-resolution
JPEG 2000 "for visual inspection only"*. Measured with the real face model (59 public photos, 300 labelled pairs, photos shrunk to
Aadhaar-like sizes; one genuine person vs a stranger):

| UIDAI photo width | genuine accepted at limit 0.60 / 0.68 / 0.75 | strangers accepted at 0.68 / 0.75 |
|---|---|---|
| ~150 px | 92% / ~100% / 100% | 0% / 1.3% |
| ~110 px | 66% / ~82% / 89% | 0.1% / 0.8% |

so `AADHAAR_PHOTO_MATCH_THRESHOLD` defaults to **0.68**. (Blurring the selfie to match the photo's resolution made it *worse*, so it
isn't done.) The server log prints `[KYC] selfie vs Aadhaar photo distance ...` for every attempt: if your genuine file is
refused, raise the limit a little above that number (keep it under ~0.72). A refused voter can simply retake the selfie.
Run `python tests/e2e_real_kyc.py` to see the numbers on your machine.

**Honest limits:** the file proves the holder controlled the Aadhaar login *recently*; someone who also controls the victim's SIM
could generate it (the face match and one-person-one-registration are the backstops). The file contains only the **last 4 digits**
of the Aadhaar number, so the other 8 typed digits are not verified (an attacker with a valid Aadhaar ending in the same 4
digits could occupy a victim's number, but only once, since the identity can register only once). The signature and hash
algorithms follow UIDAI's published specification and were tested with files signed by a local test key, **not with a genuine UIDAI
file** - test it with your own file before relying on it. Check whether your organisation must register with UIDAI to use
offline verification and what consent notice to show; this is not legal advice.

### Duplicate faces

Registration also refuses a face that is already enrolled. The old limit (0.35) only caught the *same photo*; a new photo or a webcam
capture of the same person sits at 0.4-0.6 (measured: same person across different photos median 0.42, max 0.62; different people never
closer than 0.69), so the limit is now **0.60** (`FACE_DUPLICATE_THRESHOLD`), and each voter's successful live logins and UIDAI photo are
kept as extra face templates so later look-alikes are caught too. Twins or very close relatives may be refused: they must contact the
election officer.

## Liveness detection (anti-spoofing)

After the face match the server issues a **random head-turn challenge** (3 turns, always both
directions, revealed one step at a time, read aloud for visually impaired voters). It works on 3-D
geometry: a real head turning moves the nose relative to the eyes; a flat photo or phone screen
doesn't, however it is tilted. Every frame must also contain exactly one face that is still the
registered voter, the ballot stays locked until the server marks the challenge passed, and the clock
keeps running even if no valid frames arrive.

Measured with the real detector (RetinaFace landmarks): frontal faces read ~0, a clearly turned real
head reads ~0.4, and a flat photo tilted up to 60 degrees stays within about +/-0.05 (worst case seen 0.137).

| Variable | Default | Meaning |
|---|---|---|
| `LIVENESS` | `1` | `0` disables liveness (not recommended) |
| `LIVENESS_STEPS` | `3` | head turns required (min 2) |
| `LIVENESS_TURN_MIN` | `0.20` | how far you must turn (~25 deg); keep above ~0.14 |
| `LIVENESS_CENTER_MAX` | `0.10` | tolerance for "facing the camera" |
| `LIVENESS_HOLD_FRAMES` | `2` | frames a turn must be held |
| `LIVENESS_STEP_TIMEOUT` / `_TOTAL_TIMEOUT` | `20` / `75` s | time limits |
| `LIVENESS_MAX_CHALLENGES` / `_MAX_FRAMES` | `3` / `120` | attempts before the voter must restart |
| `LIVENESS_FLIP_DIRECTIONS` | `0` | `1` if your camera delivers a **mirrored** picture, so "left" and "right" feel swapped. Each voter can also tap *swap* on the page (remembered per device) |
| `LIVENESS_ANCHOR_CENTER` / `_ANCHOR_TURNED` | `0.40` / `0.55` | max identity distance to **your own face from the match step** while facing the camera / while turned |
| `LIVENESS_DETECT_THRESHOLD` | `0.8` | RetinaFace confidence needed to see a (possibly turned) face |

During the head-turn the identity check compares each frame with the face that passed the match moments earlier in
the *same session* (same camera and lighting), using a RetinaFace crop that still works on turned heads - not the
registered photo and not the frontal-only detector. (Measured on real photos: the same person across *different*
photos has median distance 0.42 and max 0.62, different people never came closer than 0.69.)
In demo mode the page prints the live numbers (`yaw`, `identity distance`, `limit`) under the camera; if the check
rejects you, those numbers tell you which value to raise in `.env`.

Calibrate on your own camera: `python tests/liveness_probe.py --identity` (live yaw + identity distance) or `--challenge` to rehearse.
**Not stopped:** a real-time deepfake / virtual camera performing the requested turns, a good 3-D mask, or an
attacker who can film the victim and switch clips on cue. Voters who physically cannot turn their head need an
assisted (in-person) path, which is not implemented.

## Real OTP SMS

By default (demo) OTPs are printed to the server console and shown on screen. To send real SMS:

1. Copy `.env.example` to `.env` and set `SMS_PROVIDER` plus that provider's credentials
   (`twilio` or `msg91`). No extra packages needed.
2. Verify your settings: `flask --app app test-sms 9XXXXXXXXX` (sends a test code to your phone).
3. Start the app. With a real provider configured the OTP is **never** shown on screen.

The app checks the SMS settings at startup and refuses to run with an incomplete configuration.
Each mobile number is limited to 5 OTP SMS per hour (`SMS_PER_PHONE_PER_HOUR`) to stop SMS-bombing and cost abuse.

**India:** TRAI requires a DLT-registered sender ID and OTP template before carriers deliver SMS to
Indian numbers. Twilio and MSG91 both guide you through it; approval can take days, and until then
messages are blocked. MSG91 uses your approved template (`MSG91_TEMPLATE_ID`, with the `##OTP##` variable).
These integrations are written to the providers' documented APIs and tested with mocks, but not against a live account -
run `test-sms` first.

### Option B: Firebase phone verification (`SMS_PROVIDER=firebase`)

Firebase sends the SMS and checks the code **in the voter's browser**; this server only verifies the
signed result (signature, project, expiry, freshness, `phone` provider, phone number == the registered
one, single use). The server never sees or stores the OTP, and the registered number is never sent to the browser
(voters type it; they only see a masked hint like `98XXXXXX78`).

> **Cost, per Firebase's own pricing page (checked Oct 2026):** Phone Auth is *not available* on the free
> Spark plan. Real SMS needs the **Blaze (pay-as-you-go) plan** - a billing account/card, billed per SMS
> (third-party sources quote about $0.01-$0.06 per SMS depending on country; see the official rates linked from
> https://firebase.google.com/pricing). New billing accounts may get Google Cloud trial credit.
> **Firebase "test phone numbers" send no SMS and use no quota**, so you can build and demo everything for free.

**Setup steps**

1. **Create a project** at https://console.firebase.google.com -> *Add project*.
2. **Register a web app:** Project settings (gear icon) -> *General* -> *Your apps* -> `</>` Web -> give it a name ->
   *Register app*. Copy `apiKey`, `projectId`, `authDomain`, `appId` from the `firebaseConfig` shown.
   (These are public identifiers, not secrets.)
3. **Enable phone sign-in:** *Authentication* -> *Get started* -> *Sign-in method* -> *Phone* -> *Enable* -> *Save*.
4. **Add a free test number** (no SMS, no cost): in the same Phone settings open *Phone numbers for testing* and add
   e.g. `+91 98XXXXXXXX` with code `123456`. Register/log in with exactly that number in the app and enter that code.
5. **Authorized domains:** *Authentication* -> *Settings* -> *Authorized domains*. `localhost` is there by default;
   add your real domain before deploying (the reCAPTCHA check fails on unlisted domains).
6. **Fill in `.env`** (copy `.env.example`): `SMS_PROVIDER=firebase`, `FIREBASE_API_KEY`, `FIREBASE_PROJECT_ID`
   (optional: `FIREBASE_AUTH_DOMAIN`, `FIREBASE_APP_ID`). Run `python app.py` - it checks these at startup.
7. **For real SMS only:** upgrade to **Blaze** (Project overview -> *Upgrade*), then
   * *Authentication* -> *Settings* -> **SMS region policy**: allow only **India (+91)**. This is your main defence against
     SMS-pumping fraud, because the SMS is triggered from the browser and this server cannot rate-limit it.
   * Create a **budget alert** in Google Cloud Billing (there is no hard spending cap).
   * Optional: enable Firebase **App Check** for extra abuse protection.
   Firebase's own limits apply (e.g. 150 verification requests per IP per hour, 3,000 SMS per day on Firebase Authentication).

Dependencies: `PyJWT` and `cryptography` (already in `requirements.txt`); the Firebase JS SDK is loaded from Google's CDN
only on pages served in Firebase mode.

## Going to production

> **Why does the OTP still appear on screen?** Because the app is in *demo mode*. The app reads settings from a file
> named exactly **`.env`** - it never reads `.env.example` (that is only a template). With no `.env`, the app falls back
> to demo mode (fake voters, admin/admin123, OTP printed on screen). The startup banner tells you which mode is active.

### Step by step (Windows commands; Linux/macOS are the same with `cp`/`mv`)

1. **Stop the server and set the demo data aside.** A demo database contains fake voters and a fake ballot, and its
   Aadhaar hashes were made with an auto-generated key you will replace.
   `ren instance instance_demo_backup`  (a fresh `instance/` folder is created automatically)
2. **Create your secrets:** `python make_secrets.py` - choose the admin password; it prints 3 lines
   (`SECRET_KEY`, `DESHGARV_PEPPER`, `ADMIN_PASSWORD_HASH`).
3. **Create `.env`:** `copy .env.example .env`, open **`.env`** (not the example), paste the 3 lines and fill in your
   `FIREBASE_*` values. Keep `DESHGARV_DEMO=0`. Back this file up somewhere private: **if `DESHGARV_PEPPER` is lost, no
   registered voter can log in again.**
4. **Add your real candidates** (one command each; every constituency needs some, usually including NOTA):
   `flask --app app add-candidate "Asha Rao" "Party X" "New Delhi"`
5. **Check everything:** `python check_production.py` - fix every `[FAIL]`; read the `[WARN]`s.
6. **Start the production server:** `python serve.py`. Wait for `[ready] face models loaded` (first run downloads ~700 MB).
   The banner must say `PRODUCTION`, `OTP delivery : Firebase` and `.env loaded`.
7. **Put HTTPS in front** (browsers block the camera and Firebase on plain `http`, except on `localhost`). Easiest is
   Caddy, which gets certificates automatically. Caddyfile for a domain pointing at your server (ports 80 and 443 open):
   ```
   vote.example.org {
       reverse_proxy 127.0.0.1:8000
   }
   ```
   and set `TRUST_PROXY_HOPS=1` in `.env`. (Without it every voter appears to have the proxy's IP, so the per-IP rate
   limits throttle all voters together.) Use `python serve.py`, **not** bare `waitress-serve`, which silently discards the
   proxy's `X-Forwarded-*` headers.
8. **Firebase console, once per project:**
   * *Authentication -> Settings -> Authorized domains*: add `vote.example.org` (reCAPTCHA fails on unlisted domains).
   * *Authentication -> Settings -> SMS region policy*: allow **India only** - your main defence against SMS-pumping fraud.
   * Google Cloud -> *Billing -> Budgets & alerts*: set an alert (Blaze has no hard cap).
   * Google Cloud -> *APIs & Services -> Credentials*: restrict the web API key to your domain (HTTP referrers). If sign-in
     breaks afterwards, the browser console names the API to allow.
   * Optional: enable **App Check**.
9. **Test with a real phone** before announcing the site: register, receive the SMS, log in, vote, check `/results`.

Testing production mode on your own PC: use `http://localhost:8000` (not your LAN IP: secure cookies are only accepted on
HTTPS or localhost) and keep `TRUST_PROXY_HOPS=0`.

### Troubleshooting Firebase: "Security check failed" / reCAPTCHA errors

The message now names the exact Firebase error code and the web address it rejected, and the full error is in the browser
console (F12 > Console, lines starting `[FirebaseOtp]`). Work through these in order:

1. **The address in your browser's address bar must be listed** under Firebase console > Authentication > Settings >
   *Authorized domains*, exactly as you type it. `localhost` and `127.0.0.1` are different names; an IP like
   `192.168.x.x` is not accepted. Firebase's own documentation says `localhost` may not be accepted for phone sign-in,
   so for real SMS use a real domain (a free tunnel such as Cloudflare Tunnel or ngrok gives you an HTTPS domain: add it to
   the list, set `TRUST_PROXY_HOPS=1`).
2. **`FIREBASE_AUTH_DOMAIN` must be the `authDomain` from your Firebase config** (`<project>.firebaseapp.com`), *not* the
   `storageBucket` (`...firebasestorage.app`). The app refuses to start if it sees the bucket address.
3. **API key restrictions:** if you restricted the key to certain websites, the address you test from must be allowed too.
4. **Ad-blockers, VPNs and privacy extensions** can block Google's reCAPTCHA. Try a private window with extensions off.
5. **Test for free without reCAPTCHA:** in Firebase > Authentication > Sign-in method > Phone > *Phone numbers for testing*,
   add a fictional number + code, put `FIREBASE_TEST_MODE=1` in `.env`, and use that number. Only fictional test numbers work in
   this mode, and `python check_production.py` fails until you remove it, so it can't reach real voters by accident.

### Troubleshooting Firebase: the page says "code sent" but no SMS arrives

If you reach the code-entry step, Firebase **accepted** the request (the app only shows it after a successful answer) - but Firebase
never tells the browser or this server whether the SMS was actually *delivered*. So check, in this order:

1. **Is that number listed under "Phone numbers for testing"?** (Firebase console > Authentication > Sign-in method > Phone.)
   Test numbers never receive an SMS - you type the fixed code you configured. Remove the number from that list to get real SMS.
2. **Wait 2 minutes and look in blocked/spam messages.** In India, SMS from international senders is often filtered by the carrier,
   by DND settings, or by phone apps (Truecaller, "filter unknown senders"). Don't press Resend repeatedly.
3. **Try a second SIM on a different carrier.** If one network gets codes and another doesn't, the problem is carrier filtering,
   not your setup.
4. **Firebase console > Authentication > Settings > SMS region policy:** India (+91) must be allowed.
5. **Billing:** Google Cloud console > Billing: the Blaze billing account must be active and linked to this project.
6. **Browser console (F12):** `[FirebaseOtp] Firebase accepted the code request for +91 ... at <time>` confirms step 1 of this list
   was reached; the time helps you match it against Firebase's usage numbers.
7. **Still unreliable in India?** SMS delivery in India is regulated (DLT registration of sender and template). Providers built for
   it, such as MSG91, handle that and give per-message delivery reports. This app already supports it: `SMS_PROVIDER=msg91`
   (see "Option A" above). Firebase remains a fine choice if your voters' carriers deliver reliably.

Meanwhile you can keep developing without any SMS: add your own number as a Firebase test number and use its fixed code.

### Operating it

* Back up the whole `instance/` folder (database + voter photos) **and** `.env` regularly; both contain personal data - restrict
  who can read them and encrypt the disk.
* Run **one** server process (many threads are fine). Needs roughly 2-3 GB of RAM for the face models.
* Re-run `python check_production.py` after every settings change.
* Logs print to the console; never share them publicly (they contain phone numbers).

## Known limitations (read before any real use)

- **Tune the face threshold on real webcam data.** The two demo photos score 0.43 against each other, i.e. they count as the same person at 0.55.
- Liveness is a head-turn challenge (see above): it stops photos, screens and generic recordings, **not** real-time deepfakes or camera injection.
- **Votes are not encrypted.** Ballot choices are stored as plain per-candidate counters in SQLite. SHA-256 / HMAC are used for *integrity* (hash-chained ledger) and *pseudonymisation* (Aadhaar), not confidentiality. Secrecy comes from never linking a voter to a choice, plus transport encryption only if you serve over HTTPS. Voter photos, phone numbers and face templates are stored unencrypted in `instance/`.
- Aadhaar is verified through UIDAI's signed offline e-KYC file (see above), not by real-time UIDAI authentication (that needs a government licence).
- Live tallies plus per-voter timestamps let an admin infer individual votes; hide tallies until polls close for real use.
- Rate limiting is in-memory (single process).

## Layout

```
app.py            Flask app: routes, DB, OTP, registration, voting, admin
face_service.py   DeepFace wrapper (works on browser-uploaded frames)
liveness.py       head-turn liveness: geometry, challenge state machine, pose analyzer
uidai_kyc.py      verifies UIDAI offline e-KYC files (signature, share-code ZIP, mobile hash, age, identity key)
firebase_auth.py  verifies Firebase phone-sign-in ID tokens (PyJWT + cryptography)
sms_gateway.py    OTP delivery providers (console / Twilio / MSG91 / Firebase mode)
templates/ static/  UI
demo_data/        demo reference photos (private, not served)
instance/         runtime DB + voter photos + secrets (git-ignored)
tests/            pytest suite + real-DeepFace e2e script
legacy/           original prototype and notes
```
