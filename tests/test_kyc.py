"""UIDAI offline e-KYC verification (uidai_kyc.py). Files are signed with a local test key."""
import datetime
import hashlib
import os
import shutil
import sys
import time

import cv2
import numpy as np
import pytest
from cryptography.hazmat.primitives import serialization
from lxml import etree

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kyc_helpers as kh  # noqa: E402
import uidai_kyc as uk  # noqa: E402

CERTS = [kh.CERT]
IST = uk.IST
HAVE_ZIP = shutil.which("zip") is not None


def verify(zip_bytes, share="Lock@487", **kw):
    return uk.verify_offline_kyc(zip_bytes, share, kw.pop("certs", CERTS), **kw)


class TestGenuineFiles:
    def test_valid_file_is_read(self):
        r = verify(kh.kyc_zip())
        assert (r.name, r.dob, r.gender, r.last4) == ("Asha Rao", "1990-05-12", "F", "0123")
        assert len(r.photo) > 100 and r.generated_at.tzinfo is not None

    @pytest.mark.skipif(not HAVE_ZIP, reason="zip tool not installed")
    def test_legacy_zipcrypto_encryption_also_works(self):
        assert verify(kh.kyc_zip(mode="zipcrypto")).name == "Asha Rao"

    def test_unicode_names_survive(self):
        assert verify(kh.kyc_zip(name="आशा राव")).name == "आशा राव"

    def test_several_certificates_are_tried(self):
        assert verify(kh.kyc_zip(), certs=[kh.OTHER_CERT, kh.CERT]).name == "Asha Rao"


class TestForgeries:
    def tamper(self, old, new):
        xml = kh.build_xml().replace(old, new)
        return kh.make_zip(xml)

    @pytest.mark.parametrize("old,new", [(b"Asha Rao", b"Ravi Kumar"), (b"1990-05-12", b"1950-05-12"), (b'gender="F"', b'gender="M"'),
                                         (b'house="12"', b'house="99"')])
    def test_editing_any_signed_field_is_detected(self, old, new):
        with pytest.raises(uk.KycError, match="signature"):
            verify(self.tamper(old, new))

    def test_swapping_the_photo_is_detected(self):
        xml = kh.build_xml()
        photo_b64 = etree.fromstring(xml).findtext("UidData/Pht").encode()
        import base64
        evil = base64.b64encode(kh.jpeg_bytes()).decode().encode()
        with pytest.raises(uk.KycError, match="signature"):
            verify(kh.make_zip(xml.replace(photo_b64, evil)))

    def test_editing_the_mobile_hash_is_detected(self):
        xml = kh.build_xml()
        m = etree.fromstring(xml).find("UidData/Poi").get("m").encode()
        with pytest.raises(uk.KycError, match="signature"):
            verify(kh.make_zip(xml.replace(m, b"0" * 64)))

    def test_file_signed_by_anyone_else_is_rejected(self):
        with pytest.raises(uk.KycError, match="signature"):
            verify(kh.kyc_zip(priv=kh.OTHER_PRIV))

    def test_unsigned_file_is_rejected(self):
        with pytest.raises(uk.KycError, match="signature"):
            verify(kh.kyc_zip(sign=False))

    def test_no_certificate_configured_is_refused_not_ignored(self):
        with pytest.raises(uk.KycError, match="not set up"):
            verify(kh.kyc_zip(), certs=[])

    def test_signature_wrapping_attack_is_rejected(self):
        """Attacker nests the genuine signed document inside a forged outer document."""
        genuine = kh.build_xml(name="Victim Person")
        forged = (b'<OfflinePaperlessKyc referenceId="012320260101120000123"><UidData>'
                  b'<Poi name="Attacker" dob="1990-01-01" gender="M" m="' + b"0" * 64 + b'"/><Pht>AAAA</Pht></UidData>'
                  b"<Wrapped>" + genuine + b"</Wrapped></OfflinePaperlessKyc>")
        with pytest.raises(uk.KycError):
            verify(kh.make_zip(forged))

    def test_only_the_signed_part_is_ever_read(self):
        """A second, unsigned record appended at the end must invalidate the file (digest covers the whole document)."""
        xml = kh.build_xml().replace(b"</OfflinePaperlessKyc>", b'<UidData><Poi name="Evil" dob="1990-01-01" m="x"/></UidData></OfflinePaperlessKyc>')
        with pytest.raises(uk.KycError):
            verify(kh.make_zip(xml))

    def test_xml_external_entity_attack_leaks_nothing_and_is_rejected(self):
        xml = (b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
               b'<OfflinePaperlessKyc referenceId="012320260101120000123"><UidData><Poi name="&xxe;" dob="1990-01-01" m="x"/>'
               b"<Pht>AAAA</Pht></UidData></OfflinePaperlessKyc>")
        with pytest.raises(uk.KycError) as e:
            verify(kh.make_zip(xml))
        assert "root:" not in str(e.value)

    def test_entity_expansion_bomb_is_rejected_quickly(self):
        bomb = (b'<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">'
                b'<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;"><!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">]>'
                b'<OfflinePaperlessKyc referenceId="012320260101120000123"><UidData><Poi name="&d;" dob="1" m="x"/></UidData></OfflinePaperlessKyc>')
        t = time.time()
        with pytest.raises(uk.KycError):
            verify(kh.make_zip(bomb))
        assert time.time() - t < 3

    def test_sha1_signatures_are_not_accepted(self):
        import signxml
        xml = kh.build_xml(sign=False)
        try:
            signer = signxml.XMLSigner(method=signxml.methods.enveloped, signature_algorithm="rsa-sha1", digest_algorithm="sha1",
                                       c14n_algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315")
            signed = signer.sign(etree.fromstring(xml), key=kh.PRIV, cert=kh.CERT.public_bytes(serialization.Encoding.PEM))
        except Exception:
            pytest.skip("signxml refuses to create SHA-1 signatures here")
        ki = signed.find(f"{kh.DS}Signature/{kh.DS}KeyInfo"); ki.getparent().remove(ki)
        with pytest.raises(uk.KycError):
            verify(kh.make_zip(etree.tostring(signed)))


class TestZipHandling:
    def test_wrong_share_code(self):
        with pytest.raises(uk.KycError, match="share code"):
            verify(kh.kyc_zip(), share="WRONG")

    @pytest.mark.skipif(not HAVE_ZIP, reason="zip tool not installed")
    def test_wrong_share_code_legacy_zip(self):
        with pytest.raises(uk.KycError):
            verify(kh.kyc_zip(mode="zipcrypto"), share="WRONG")

    @pytest.mark.parametrize("junk", [b"", b"not a zip at all", b"PK\x03\x04garbage"])
    def test_not_a_zip(self, junk):
        with pytest.raises(uk.KycError):
            verify(junk)

    def test_oversized_upload(self):
        with pytest.raises(uk.KycError, match="too large"):
            verify(b"x" * (uk.MAX_ZIP_BYTES + 1))

    def test_empty_share_code(self):
        with pytest.raises(uk.KycError, match="share code"):
            verify(kh.kyc_zip(), share="")

    def test_zip_with_two_files_or_a_non_xml_file(self):
        import io, pyzipper
        for files in ({"a.xml": b"<a/>", "b.xml": b"<b/>"}, {"photo.jpg": b"x"}):
            buf = io.BytesIO()
            with pyzipper.AESZipFile(buf, "w", encryption=pyzipper.WZ_AES) as zf:
                zf.setpassword(b"Lock@487")
                for n, d in files.items():
                    zf.writestr(n, d)
            with pytest.raises(uk.KycError, match="exactly one XML"):
                verify(buf.getvalue())

    def test_decompression_bomb_is_refused(self):
        import io, pyzipper
        buf = io.BytesIO()
        with pyzipper.AESZipFile(buf, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zf:
            zf.setpassword(b"Lock@487")
            zf.writestr("big.xml", b"<a>" + b"A" * 6_000_000 + b"</a>")
        assert len(buf.getvalue()) < uk.MAX_ZIP_BYTES                     # tiny on the wire...
        with pytest.raises(uk.KycError, match="too large"):                # ...huge when unpacked
            verify(buf.getvalue())


class TestFields:
    def now(self):
        return datetime.datetime.now(IST)

    def test_stale_file_rejected_and_age_is_configurable(self):
        old = self.now() - datetime.timedelta(days=4)
        z = kh.kyc_zip(generated=old)
        with pytest.raises(uk.KycError, match="too old"):
            verify(z)
        assert verify(z, max_age_days=10).name == "Asha Rao"

    def test_future_dated_file_rejected(self):
        with pytest.raises(uk.KycError, match="future"):
            verify(kh.kyc_zip(generated=self.now() + datetime.timedelta(days=5)))

    @pytest.mark.parametrize("ref", ["123", "abcd20260101120000123", "0123202613991200001239", "012320261301120000123"])
    def test_bad_reference_ids(self, ref):
        with pytest.raises(uk.KycError):
            verify(kh.kyc_zip(ref=ref))

    @pytest.mark.parametrize("attr", ["name", "dob", "m"])
    def test_missing_required_attribute(self, attr):
        with pytest.raises(uk.KycError, match="missing"):
            verify(kh.kyc_zip(drop_poi_attr=attr))

    def test_reference_id_carries_last_four_digits(self):
        assert verify(kh.kyc_zip(aadhaar="999988887777")).last4 == "7777"


class TestMobileHash:
    @pytest.mark.parametrize("digit,rounds", [("0", 1), ("1", 1), ("2", 2), ("5", 5), ("9", 9)])
    def test_hash_rounds_follow_the_last_aadhaar_digit(self, digit, rounds):
        h = hashlib.sha256(b"1234567890Lock@487").hexdigest()          # independent re-implementation of the UIDAI recipe
        for _ in range(rounds - 1):
            h = hashlib.sha256(h.encode()).hexdigest()
        assert uk.mobile_hash("1234567890", "Lock@487", digit) == h

    def test_uidai_documented_example_shape(self):
        # "Sha256(Sha256(1234567890Lock@487))" for an Aadhaar ending in 2
        inner = hashlib.sha256(b"1234567890Lock@487").hexdigest()
        assert uk.mobile_hash("1234567890", "Lock@487", "2") == hashlib.sha256(inner.encode()).hexdigest()

    def test_check_mobile(self):
        r = verify(kh.kyc_zip(aadhaar="234567890123", mobile="9812345678"))
        assert uk.check_mobile(r, "9812345678", "Lock@487", "234567890123")
        assert not uk.check_mobile(r, "9812345679", "Lock@487", "234567890123")        # other number
        assert not uk.check_mobile(r, "9812345678", "Other", "234567890123")            # other share code
        assert not uk.check_mobile(r, "9812345678", "Lock@487", "234567890124")         # other last digit


class TestEligibilityAndIdentity:
    TODAY = datetime.date(2026, 10, 7)

    @pytest.mark.parametrize("dob,ok", [("2008-10-07", True), ("2008-10-08", False), ("2000-01-01", True), ("07-10-2008", True),
                                        ("08-10-2008", False), ("2009-01-01", False), ("1990", True), ("2008", False), ("2007", True)])
    def test_age_gate(self, dob, ok):
        assert uk.is_old_enough(dob, self.TODAY, 18) is ok

    def test_age_gate_can_be_disabled(self):
        assert uk.is_old_enough("2020-01-01", self.TODAY, 0)

    def test_unreadable_dob(self):
        with pytest.raises(uk.KycError):
            uk.is_old_enough("yesterday", self.TODAY, 18)

    def test_identity_key_is_stable_per_person_and_secret_dependent(self):
        r = verify(kh.kyc_zip())
        same_other_file = verify(kh.kyc_zip(name="  ASHA   rao ", aadhaar="999900000123", mobile="9000000001"))
        assert uk.identity_key(r, "pep") == uk.identity_key(same_other_file, "pep")          # case/space/other number: same person
        assert uk.identity_key(r, "pep") != uk.identity_key(r, "other-pepper")
        for kw in ({"name": "Asha Rai"}, {"dob": "1990-05-13"}, {"gender": "M"}, {"aadhaar": "234567890124"}):
            assert uk.identity_key(verify(kh.kyc_zip(**kw)), "pep") != uk.identity_key(r, "pep")


class TestPhotoAndCerts:
    def test_small_photos_are_enlarged_for_face_detection(self):
        r = verify(kh.kyc_zip(photo=kh.jpeg_bytes(size=(80, 100))))
        assert uk.decode_photo(r.photo).shape[1] >= 240

    def test_uidais_jpeg2000_photo_format_is_decoded(self):
        """UIDAI: "Pht ... is present in JP2000 format with low resolution"."""
        r = verify(kh.kyc_zip(photo=kh.jp2_bytes(size=(90, 110))))
        img = uk.decode_photo(r.photo)
        assert img.shape[1] >= 240 and img.shape[2] == 3

    def test_pillow_fallback_decodes_jpeg2000_when_opencv_cannot(self, monkeypatch):
        monkeypatch.setattr(cv2, "imdecode", lambda *a, **k: None)
        assert uk.decode_photo(kh.jp2_bytes(size=(120, 150))).shape[2] == 3

    def test_unreadable_photo(self):
        with pytest.raises(uk.KycError, match="photo"):
            uk.decode_photo(b"not an image")

    def test_certificates_load_from_pem_and_der_and_describe(self, tmp_path):
        (tmp_path / "a.pem").write_bytes(kh.CERT.public_bytes(serialization.Encoding.PEM))
        (tmp_path / "b.cer").write_bytes(kh.OTHER_CERT.public_bytes(serialization.Encoding.DER))
        (tmp_path / "readme.txt").write_text("ignored")
        certs = uk.load_certs(str(tmp_path))
        assert len(certs) == 2 and "valid until" in uk.describe_cert(certs[0])
        assert verify(kh.kyc_zip(), certs=certs).name == "Asha Rao"

    def test_garbage_certificate_file_is_reported(self, tmp_path):
        (tmp_path / "bad.cer").write_bytes(b"this is not a certificate")
        with pytest.raises(ValueError, match="not a valid certificate"):
            uk.load_certs(str(tmp_path))

    def test_empty_directory(self, tmp_path):
        assert uk.load_certs(str(tmp_path)) == []
