"""Builds UIDAI-style offline e-KYC files signed with a LOCAL test key (never a real UIDAI file)."""
import base64
import datetime
import io
import os
import shutil
import subprocess
import sys
import tempfile

import cv2
import numpy as np
import pyzipper
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from lxml import etree
from signxml import XMLSigner, methods

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import uidai_kyc  # noqa: E402

DS = "{http://www.w3.org/2000/09/xmldsig#}"


def make_identity(cn="Test UIDAI Signing Key"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1)
            .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=365))
            .sign(key, hashes.SHA256()))
    priv = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return priv, cert


PRIV, CERT = make_identity()
OTHER_PRIV, OTHER_CERT = make_identity("Someone else")


def jpeg_bytes(img=None, size=(110, 140)):
    if img is None:
        img = np.random.randint(0, 255, (size[1], size[0], 3), dtype=np.uint8)
    ok, buf = cv2.imencode(".jpg", img, [cv2.IMWRITE_JPEG_QUALITY, 80])
    assert ok
    return buf.tobytes()


def jp2_bytes(img=None, size=(110, 140)):
    """UIDAI stores the photo as a low-resolution JPEG 2000."""
    if img is None:
        img = np.random.randint(0, 255, (size[1], size[0], 3), dtype=np.uint8)
    ok, buf = cv2.imencode(".jp2", img)
    assert ok
    return buf.tobytes()


def build_xml(name="Asha Rao", dob="1990-05-12", gender="F", aadhaar="234567890123", mobile="9812345678",
              share="Lock@487", generated=None, photo=None, ref=None, sign=True, priv=None, drop_poi_attr=None):
    generated = generated or datetime.datetime.now(uidai_kyc.IST)
    ref = ref or (aadhaar[-4:] + generated.strftime("%Y%m%d%H%M%S") + "123")
    photo = photo if photo is not None else jpeg_bytes()
    root = etree.Element("OfflinePaperlessKyc", referenceId=ref)
    data = etree.SubElement(root, "UidData")
    poi = etree.SubElement(data, "Poi", name=name, dob=dob, gender=gender, e="x" * 64,
                           m=uidai_kyc.mobile_hash(mobile, share, aadhaar[-1]))
    if drop_poi_attr:
        del poi.attrib[drop_poi_attr]
    etree.SubElement(data, "Poa", careof="C/O Someone", house="12", pc="110001", state="Delhi")
    etree.SubElement(data, "Pht").text = base64.b64encode(photo).decode()
    if sign:
        signer = XMLSigner(method=methods.enveloped, signature_algorithm="rsa-sha256", digest_algorithm="sha256",
                           c14n_algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315")
        root = signer.sign(root, key=priv or PRIV, cert=CERT.public_bytes(serialization.Encoding.PEM))
        ki = root.find(f"{DS}Signature/{DS}KeyInfo")           # real UIDAI signatures carry no KeyInfo
        ki.getparent().remove(ki)
    return etree.tostring(root)


def make_zip(xml, share="Lock@487", mode="aes", name="offlineaadhaar20260101120000.xml"):
    if mode == "aes":
        buf = io.BytesIO()
        with pyzipper.AESZipFile(buf, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zf:
            zf.setpassword(share.encode())
            zf.writestr(name, xml)
        return buf.getvalue()
    if mode == "zipcrypto":                                    # legacy encryption, via the zip command-line tool
        d = tempfile.mkdtemp()
        open(os.path.join(d, name), "wb").write(xml)
        out = os.path.join(d, "out.zip")
        subprocess.run(["zip", "-j", "-q", "-P", share, out, os.path.join(d, name)], check=True)
        data = open(out, "rb").read()
        shutil.rmtree(d)
        return data
    raise ValueError(mode)


def kyc_zip(share="Lock@487", mode="aes", **xml_kwargs):
    return make_zip(build_xml(share=share, **xml_kwargs), share, mode)
