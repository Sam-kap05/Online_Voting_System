"""
Verification of UIDAI "Aadhaar Paperless Offline e-KYC" files.

WHAT THIS PROVES
----------------
An Aadhaar holder can download a ZIP from UIDAI's own website (login with Aadhaar/VID + an OTP sent to the
Aadhaar-LINKED mobile). The ZIP is protected with a "share code" the holder chooses and contains an XML signed by
UIDAI: name, date of birth, gender, a photo, the LAST 4 digits of the Aadhaar number, and a HASH of the linked mobile.
Anyone can check UIDAI's signature with UIDAI's published public certificate - no UIDAI licence or API access needed.

So a valid, recent file proves that whoever supplied it controlled that person's Aadhaar login moments ago. Merely
KNOWING an Aadhaar number gives you nothing. We additionally bind the file to:
  * the 12-digit number typed in (last 4 digits must match the file),
  * the mobile that will receive our OTP (hash recipe from UIDAI's spec),
  * the voter's live selfie (face match against the UIDAI-signed photo - done by the caller),
  * eligibility (age) and uniqueness (``identity_key``: one real person -> one registration).

WHAT THIS DOES NOT DO
---------------------
It is not real-time authentication against UIDAI's database (that needs a UIDAI AUA/KUA licence). Someone who controls
the victim's SIM *and* Aadhaar login could still generate a file; the face match and one-person-one-registration
rules are the backstops.

PRIVACY: the file, the share code and the photo are processed in memory and never stored. UIDAI's terms say the
service provider shall not share, publish or display the XML or the share code.

The algorithms here follow UIDAI's published specification and sample code. They were tested with files signed
by a local test key, NOT with a genuine UIDAI file (none is available to the author): try it with your own file.
"""
from __future__ import annotations

import base64
import glob
import hashlib
import hmac
import io
import os
import re
import unicodedata
import zlib
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from typing import List, Optional

import cv2
import numpy as np
import pyzipper
from cryptography import x509
from lxml import etree
from signxml import (DigestAlgorithm, SignatureConfiguration, SignatureMethod, XMLVerifier)
from signxml import exceptions as sx_exc

IST = timezone(timedelta(hours=5, minutes=30))
MAX_ZIP_BYTES = 1_000_000          # real files are ~30-60 KB
MAX_XML_BYTES = 2_000_000
MAX_PHOTO_B64 = 600_000


class KycError(Exception):
    """The file is not acceptable. The message is safe to show to the voter."""


@dataclass
class KycRecord:
    name: str
    dob: str
    gender: str
    last4: str
    generated_at: datetime
    mobile_hash: str
    photo: bytes


# ====================================================================== certificates
def find_cert_files(directory: str) -> List[str]:
    out: List[str] = []
    for pattern in ("*.cer", "*.crt", "*.pem", "*.der"):
        out += glob.glob(os.path.join(directory, pattern))
    return sorted(out)


def load_cert(path: str):
    data = open(path, "rb").read()
    try:
        return x509.load_pem_x509_certificate(data) if b"-----BEGIN" in data else x509.load_der_x509_certificate(data)
    except ValueError as exc:
        raise ValueError(f"{os.path.basename(path)} is not a valid certificate: {exc}")


def load_certs(directory: str):
    return [load_cert(p) for p in find_cert_files(directory)]


def describe_cert(cert) -> str:
    try:
        cn = cert.subject.rfc4514_string()
    except Exception:
        cn = "?"
    return f"{cn} (valid until {cert.not_valid_after_utc.date()})"


# ============================================================================== zip + xml
def open_kyc_zip(zip_bytes: bytes, share_code: str) -> bytes:
    if not zip_bytes or len(zip_bytes) > MAX_ZIP_BYTES:
        raise KycError("That file is empty or too large to be an Aadhaar offline e-KYC file.")
    if not share_code or len(share_code) > 64:
        raise KycError("Please enter the share code you chose when you downloaded the file.")
    try:
        zf = pyzipper.AESZipFile(io.BytesIO(zip_bytes))
    except (pyzipper.BadZipFile, ValueError, EOFError):
        raise KycError("That is not a valid Aadhaar offline e-KYC ZIP file. Upload the ZIP exactly as downloaded from UIDAI.")
    members = [i for i in zf.infolist() if not i.is_dir()]
    if len(members) != 1 or not members[0].filename.lower().endswith(".xml"):
        raise KycError("The ZIP must contain exactly one XML file, as downloaded from UIDAI.")
    if members[0].file_size > MAX_XML_BYTES:
        raise KycError("The XML inside the ZIP is too large to be genuine.")
    zf.setpassword(share_code.encode("utf-8"))
    try:
        with zf.open(members[0]) as fh:
            data = fh.read(MAX_XML_BYTES + 1)
    except (RuntimeError, pyzipper.BadZipFile, zlib.error, ValueError, EOFError):
        raise KycError("Could not open the file - the share code is probably wrong.")
    if len(data) > MAX_XML_BYTES:
        raise KycError("The XML inside the ZIP is too large to be genuine.")
    return data


_PARSER = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False, huge_tree=False, dtd_validation=False)
_CONFIG = SignatureConfiguration(
    require_x509=False,                                     # UIDAI signatures carry no KeyInfo: we supply the cert
    signature_methods=frozenset({SignatureMethod.RSA_SHA256}),
    digest_algorithms=frozenset({DigestAlgorithm.SHA256}),  # no SHA-1
)


def verify_signature(xml_bytes: bytes, certs) -> etree._Element:
    """Return the root element that UIDAI's signature covers. Only THIS element may be trusted, never the raw input."""
    if not certs:
        raise KycError("Aadhaar verification is not set up on this server (no UIDAI certificate).")
    try:
        etree.fromstring(xml_bytes, parser=_PARSER)         # fail fast on malformed XML / entity bombs
    except etree.XMLSyntaxError:
        raise KycError("The file does not contain valid XML.")
    last_error: Optional[Exception] = None
    for cert in certs:
        try:
            result = XMLVerifier().verify(xml_bytes, x509_cert=cert, expect_config=_CONFIG, parser=_PARSER)
        except (sx_exc.SignXMLException, etree.XMLSyntaxError, ValueError) as exc:
            last_error = exc
            continue
        signed = result.signed_xml
        if signed is None or etree.QName(signed).localname != "OfflinePaperlessKyc":
            raise KycError("The signature does not cover the whole Aadhaar document.")
        return signed
    print(f"[KYC] signature rejected: {type(last_error).__name__ if last_error else 'no certificate matched'}")
    raise KycError("UIDAI's digital signature on this file is not valid. Download a fresh file from the UIDAI website "
                   "and do not edit it.")


def parse_record(signed_root: etree._Element) -> KycRecord:
    ref = signed_root.get("referenceId", "")
    m = re.fullmatch(r"(\d{4})(\d{17})", ref)
    if not m:
        raise KycError("The file has no valid reference id.")
    try:
        generated = datetime.strptime(m.group(2)[:14], "%Y%m%d%H%M%S").replace(tzinfo=IST)
    except ValueError:
        raise KycError("The file has an invalid creation time.")
    poi = signed_root.find("UidData/Poi")
    pht = signed_root.findtext("UidData/Pht") or ""
    if poi is None or not poi.get("name") or not poi.get("dob") or not poi.get("m") or not pht:
        raise KycError("The file is missing required details (name, date of birth, mobile or photo).")
    if len(pht) > MAX_PHOTO_B64:
        raise KycError("The photo in the file is too large to be genuine.")
    try:
        photo = base64.b64decode(pht, validate=False)
    except ValueError:
        raise KycError("The photo in the file is corrupt.")
    name = " ".join(unicodedata.normalize("NFC", poi.get("name")).split())
    if not 1 <= len(name) <= 120:
        raise KycError("The name in the file is not valid.")
    return KycRecord(name=name, dob=poi.get("dob").strip(), gender=(poi.get("gender") or "").strip().upper()[:1],
                     last4=m.group(1), generated_at=generated, mobile_hash=poi.get("m").strip().lower(), photo=photo)


# ================================================================================ checks
def check_fresh(record: KycRecord, now: Optional[datetime] = None, max_age_days: float = 3) -> None:
    now = now or datetime.now(IST)
    if record.generated_at > now + timedelta(days=1):
        raise KycError("The file's creation time is in the future - the file is not genuine.")
    if now - record.generated_at > timedelta(days=max_age_days):
        raise KycError(f"This file is too old. Download a fresh one from UIDAI (it must be less than {max_age_days:g} days old).")


def mobile_hash(mobile: str, share_code: str, aadhaar_last_digit: str) -> str:
    """UIDAI: Sha256(Sha256(Mobile+ShareCode)) repeated 'last digit of the Aadhaar number' times (0 -> once).
    Each round hashes the previous round's lowercase hex digest."""
    rounds = int(aadhaar_last_digit) or 1
    digest = hashlib.sha256((mobile + share_code).encode("utf-8")).hexdigest()
    for _ in range(rounds - 1):
        digest = hashlib.sha256(digest.encode("utf-8")).hexdigest()
    return digest


def check_mobile(record: KycRecord, mobile: str, share_code: str, aadhaar: str) -> bool:
    return hmac.compare_digest(mobile_hash(mobile, share_code, aadhaar[-1]), record.mobile_hash)


def _parse_dob(dob: str) -> tuple:
    """-> (year, month|None, day|None)"""
    for fmt in ("%Y-%m-%d", "%d-%m-%Y"):
        try:
            d = datetime.strptime(dob, fmt)
            return d.year, d.month, d.day
        except ValueError:
            pass
    if re.fullmatch(r"\d{4}", dob):
        return int(dob), None, None
    raise KycError("The date of birth in the file is not readable.")


def is_old_enough(dob: str, today: date, min_age: int) -> bool:
    if min_age <= 0:
        return True
    year, month, day = _parse_dob(dob)
    if month is None:                       # year-only DOB: only certain once the whole birth year is >= min_age ago
        return today.year - year > min_age
    age = today.year - year - ((today.month, today.day) < (month, day))
    return age >= min_age


def identity_key(record: KycRecord, pepper: str) -> str:
    """Stable per real person (name + date of birth + gender + last 4 digits), independent of which file/number is used.
    Keyed with the server pepper so it cannot be brute-forced from a database leak."""
    norm = " ".join(unicodedata.normalize("NFKC", record.name).casefold().split())
    msg = f"kyc|{norm}|{record.dob}|{record.gender}|{record.last4}".encode()
    return hmac.new(pepper.encode(), msg, hashlib.sha256).hexdigest()


def decode_photo(photo: bytes, min_width: int = 240) -> np.ndarray:
    """The signed photo as a BGR image, upscaled if tiny (Aadhaar photos are small) so face detectors can see it."""
    img = cv2.imdecode(np.frombuffer(photo, np.uint8), cv2.IMREAD_COLOR)
    if img is None:
        try:
            from PIL import Image
            img = cv2.cvtColor(np.array(Image.open(io.BytesIO(photo)).convert("RGB")), cv2.COLOR_RGB2BGR)
        except Exception:
            raise KycError("The photo inside the Aadhaar file could not be read.")
    h, w = img.shape[:2]
    if w < min_width:
        scale = min_width / float(w)
        img = cv2.resize(img, (min_width, int(h * scale)), interpolation=cv2.INTER_CUBIC)
    return img


def verify_offline_kyc(zip_bytes: bytes, share_code: str, certs, now: Optional[datetime] = None,
                       max_age_days: float = 3) -> KycRecord:
    """ZIP + share code -> a record whose contents UIDAI has signed (or KycError)."""
    xml = open_kyc_zip(zip_bytes, share_code)
    record = parse_record(verify_signature(xml, certs))
    check_fresh(record, now, max_age_days)
    return record
