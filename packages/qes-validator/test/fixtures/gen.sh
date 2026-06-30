#!/usr/bin/env bash
# Deterministic QES test fixtures — generated offline with openssl (no runtime deps, no infra).
# Produces: a test Root CA, a QUALIFIED leaf (id-pe-qcStatements: QcCompliance + QcType-eSign),
# a NON-qualified leaf (no qcStatements), and a TSA-EKU leaf (for the refinement-3 TSA-vs-CA/QC trap).
# All are TEST material; never trust roots — the validator injects this root only in tests.
set -euo pipefail
cd "$(dirname "$0")"
D=.

# ---- Root CA ----
openssl ecparam -name prime256v1 -genkey -noout -out $D/root.key.pem
openssl req -x509 -new -key $D/root.key.pem -sha256 -days 7300 \
  -subj "/C=FR/O=VAL Test Trust Services/CN=VAL Test Root CA QC" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out $D/root.cert.pem

# ---- qcStatements extension config (QcCompliance 0.4.0.1862.1.1 + QcType-eSign 0.4.0.1862.1.6.1) ----
cat > $D/qc.ext <<'EXT'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,nonRepudiation
1.3.6.1.5.5.7.1.3=ASN1:SEQUENCE:qcStatements
[qcStatements]
qcCompliance=SEQUENCE:qc_compliance
qcType=SEQUENCE:qc_type
[qc_compliance]
id=OID:0.4.0.1862.1.1
[qc_type]
id=OID:0.4.0.1862.1.6
types=SEQUENCE:qc_type_list
[qc_type_list]
esign=OID:0.4.0.1862.1.6.1
EXT

mk_leaf () { # name subj extfile
  openssl ecparam -name prime256v1 -genkey -noout -out $D/$1.key.pem
  openssl req -new -key $D/$1.key.pem -subj "$2" -out $D/$1.csr.pem
  openssl x509 -req -in $D/$1.csr.pem -CA $D/root.cert.pem -CAkey $D/root.key.pem \
    -CAcreateserial -sha256 -days 3650 -extfile "$3" -out $D/$1.cert.pem
}

mk_leaf qualified "/C=FR/O=ACME SAS/CN=Alice Signer/GN=Alice/SN=Signer" $D/qc.ext

# non-qualified leaf (plain, no qcStatements)
cat > $D/plain.ext <<'EXT'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
EXT
mk_leaf plain "/C=US/O=Demo Inc/CN=Bob Demo/GN=Bob/SN=Demo" $D/plain.ext

# sign a leaf from an ALREADY-GENERATED key (mk_leaf hardcodes P-256, so use this for other key types)
sign_leaf () { # name subj extfile hashalg
  openssl req -new -key $D/$1.key.pem -subj "$2" -out $D/$1.csr.pem
  openssl x509 -req -in $D/$1.csr.pem -CA $D/root.cert.pem -CAkey $D/root.key.pem \
    -CAcreateserial -$4 -days 3650 -extfile "$3" -out $D/$1.cert.pem
}
# ES384 qualified leaf (exercises the ES384 verify branch), issued by the same root
openssl ecparam -name secp384r1 -genkey -noout -out $D/qualified-es384.key.pem
sign_leaf qualified-es384 "/C=FR/O=ACME SAS/CN=Carol P384/GN=Carol/SN=P384" $D/qc.ext sha384
# RSA qualified leaf (exercises the PS256 / RSA-PSS verify branch), issued by the same root
openssl genrsa -out $D/qualified-rsa.key.pem 2048 2>/dev/null
sign_leaf qualified-rsa "/C=FR/O=ACME SAS/CN=Dan RSA/GN=Dan/SN=RSA" $D/qc.ext sha256

# ── RFC 5280 §6 path-validation fixtures (multi-level CA hierarchy) ──────────────────────────────────
# generic signer with an explicit issuing CA (name subj extfile hashalg caname)
sign_by () {
  openssl req -new -key $D/$1.key.pem -subj "$2" -out $D/$1.csr.pem
  openssl x509 -req -in $D/$1.csr.pem -CA $D/$5.cert.pem -CAkey $D/$5.key.pem \
    -CAcreateserial -$4 -days 3650 -extfile "$3" -out $D/$1.cert.pem
}
ca_ext () { printf 'basicConstraints=critical,CA:TRUE%s\nkeyUsage=critical,keyCertSign,cRLSign\n' "$1" > "$2"; }
ca_ext ',pathlen:2' $D/ca2.ext   # intermediate: up to 2 CAs below
ca_ext ',pathlen:0' $D/ca0.ext   # issuing: NO CA below (pathlen:0)

# 4-cert chain: root → intermediate(pathlen:2) → issuing(pathlen:0) → leaf4(qualified)
openssl ecparam -name prime256v1 -genkey -noout -out $D/int.key.pem
sign_by int "/C=FR/O=VAL Test Trust Services/CN=VAL Test Intermediate CA" $D/ca2.ext sha256 root
openssl ecparam -name prime256v1 -genkey -noout -out $D/issuing.key.pem
sign_by issuing "/C=FR/O=VAL Test Trust Services/CN=VAL Test Issuing CA" $D/ca0.ext sha256 int
openssl ecparam -name prime256v1 -genkey -noout -out $D/leaf4.key.pem
sign_by leaf4 "/C=FR/O=ACME SAS/CN=Eve Deep/GN=Eve/SN=Deep" $D/qc.ext sha256 issuing

# attacker self-signed root + a qualified-looking leaf under it (chain internally verifies, NOT on any TL)
openssl ecparam -name prime256v1 -genkey -noout -out $D/attacker-root.key.pem
openssl req -x509 -new -key $D/attacker-root.key.pem -sha256 -days 3650 \
  -subj "/C=XX/O=Totally Legit CA/CN=Attacker Self-Signed Root" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out $D/attacker-root.cert.pem
openssl ecparam -name prime256v1 -genkey -noout -out $D/attacker-leaf.key.pem
sign_by attacker-leaf "/C=XX/O=ACME SAS/CN=Mallory Forge/GN=Mallory/SN=Forge" $D/qc.ext sha256 attacker-root

# RFC 5280 negatives:
#  (a) a "CA" with cA=FALSE that nonetheless signs a leaf
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n' > $D/notca.ext
openssl ecparam -name prime256v1 -genkey -noout -out $D/notca.key.pem
sign_by notca "/C=FR/O=Bad/CN=Not A CA" $D/notca.ext sha256 root
openssl ecparam -name prime256v1 -genkey -noout -out $D/leaf-under-notca.key.pem
sign_by leaf-under-notca "/C=FR/O=ACME SAS/CN=Frank/GN=Frank/SN=Caf" $D/qc.ext sha256 notca
#  (b) a sub-CA below the pathlen:0 issuing CA, then a leaf under it → pathLenConstraint violation
ca_ext '' $D/caN.ext
openssl ecparam -name prime256v1 -genkey -noout -out $D/subca.key.pem
sign_by subca "/C=FR/O=VAL Test Trust Services/CN=VAL Test Sub CA (illegal under pathlen0)" $D/caN.ext sha256 issuing
openssl ecparam -name prime256v1 -genkey -noout -out $D/leaf-pathlen.key.pem
sign_by leaf-pathlen "/C=FR/O=ACME SAS/CN=Grace/GN=Grace/SN=Path" $D/qc.ext sha256 subca

# item 1 — a cert checkIssued ACCEPTS as issuer (keyUsage has keyCertSign, SKI present) but with
# basicConstraints cA=FALSE → must be rejected by the EXPLICIT cA=TRUE check, not by checkIssued.
cat > $D/fakeca.ext <<'EXT'
basicConstraints=critical,CA:FALSE
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
EXT
openssl ecparam -name prime256v1 -genkey -noout -out $D/fakeca.key.pem
sign_by fakeca "/C=FR/O=Bad/CN=Fake CA (keyCertSign but cA=FALSE)" $D/fakeca.ext sha256 root
cat > $D/leaf-fakeca.ext <<'EXT'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,nonRepudiation
authorityKeyIdentifier=keyid
EXT
openssl ecparam -name prime256v1 -genkey -noout -out $D/leaf-fakeca.key.pem
sign_by leaf-fakeca "/C=FR/O=ACME SAS/CN=Heidi/GN=Heidi/SN=Fake" $D/leaf-fakeca.ext sha256 fakeca

echo "── verify qualified leaf carries qcStatements ──"
openssl x509 -in $D/qualified.cert.pem -noout -text | grep -A6 -i 'qcstatement\|1.3.6.1.5.5.7.1.3\|Qualified' || true
rm -f $D/*.csr.pem $D/*.srl
echo "DONE — fixtures in $(pwd)"
ls -1 *.pem
