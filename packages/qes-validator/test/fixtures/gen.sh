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

echo "── verify qualified leaf carries qcStatements ──"
openssl x509 -in $D/qualified.cert.pem -noout -text | grep -A6 -i 'qcstatement\|1.3.6.1.5.5.7.1.3\|Qualified' || true
rm -f $D/*.csr.pem $D/*.srl
echo "DONE — fixtures in $(pwd)"
ls -1 *.pem
