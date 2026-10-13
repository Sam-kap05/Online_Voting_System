Put UIDAI's PUBLIC certificate (.cer / .crt / .pem) in this folder.

The server uses it to check UIDAI's digital signature on the "Aadhaar Paperless Offline e-KYC" files that voters upload.
Without it the app refuses to start when AADHAAR_KYC=offline_xml (the production default).

Where to get it
  https://uidai.gov.in/en/aadhaar-paperless-offline-e-kyc   ->  "Get Certificate from here"
  (UIDAI also lists older certificates for files downloaded before 7 June 2020 and 18 June 2019: add them too if you need to
   accept such files; every certificate in this folder is tried.)

It is a public certificate (not a secret), so it is fine to keep it in your project. Check what you downloaded:
  python check_production.py        (prints the certificate subject and expiry)

Never put anything else here. UIDAI may publish a new certificate when the old one expires: replace it then.
