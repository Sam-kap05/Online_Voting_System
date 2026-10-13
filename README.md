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
python tests/liveness_probe.py          # calibrate head-turn thresholds on your webcam
```

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

## Going to production (DESHGARV_DEMO=0)

The app refuses to start unless these are set:

| Variable | Purpose |
|---|---|
| `SECRET_KEY` | Flask session signing |
| `DESHGARV_PEPPER` | key for hashing Aadhaar numbers / OTPs (never change after launch) |
| `ADMIN_PASSWORD_HASH` | from `flask --app app hash-password` |
| `SMS_PROVIDER` + its credentials | OTP delivery: `twilio`, `msg91` or `firebase` - see **Real OTP SMS** |

Optional: `ADMIN_USERNAME`, `DESHGARV_CONSTITUENCIES="A,B"`, `FACE_MATCH_THRESHOLD` (default 0.55),
`FACE_DUPLICATE_THRESHOLD` (0.35, `0` disables), `DESHGARV_DB`, `DESHGARV_PHOTO_DIR`.
Add candidates: `flask --app app add-candidate "Name" "Party" "Constituency"`.
Serve over HTTPS, one process: `gunicorn -w 1 --threads 4 "app:create_app()"`.

## Known limitations (read before any real use)

- **Tune the face threshold on real webcam data.** The two demo photos score 0.43 against each other, i.e. they count as the same person at 0.55.
- Liveness is a head-turn challenge (see above): it stops photos, screens and generic recordings, **not** real-time deepfakes or camera injection.
- **Votes are not encrypted.** Ballot choices are stored as plain per-candidate counters in SQLite. SHA-256 / HMAC are used for *integrity* (hash-chained ledger) and *pseudonymisation* (Aadhaar), not confidentiality. Secrecy comes from never linking a voter to a choice, plus transport encryption only if you serve over HTTPS. Voter photos, phone numbers and face templates are stored unencrypted in `instance/`.
- **Aadhaar is not verified with UIDAI**; the OTP only proves control of the phone number given.
- Live tallies plus per-voter timestamps let an admin infer individual votes; hide tallies until polls close for real use.
- Rate limiting is in-memory (single process).

## Layout

```
app.py            Flask app: routes, DB, OTP, registration, voting, admin
face_service.py   DeepFace wrapper (works on browser-uploaded frames)
liveness.py       head-turn liveness: geometry, challenge state machine, pose analyzer
firebase_auth.py  verifies Firebase phone-sign-in ID tokens (PyJWT + cryptography)
sms_gateway.py    OTP delivery providers (console / Twilio / MSG91 / Firebase mode)
templates/ static/  UI
demo_data/        demo reference photos (private, not served)
instance/         runtime DB + voter photos + secrets (git-ignored)
tests/            pytest suite + real-DeepFace e2e script
legacy/           original prototype and notes
```
