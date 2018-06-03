#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import time
import base64
from OpenSSL import crypto
import hashlib
from flask import Flask, request, jsonify, abort, make_response, render_template, json
from prometheus_client import generate_latest, REGISTRY, Counter, Gauge, Histogram


VERSION = "1.0"

DEFAULT_CONFIG = dict(
    host='0.0.0.0',
    port=8080,
    ca_infra_file='ca_infra.pem',
    ca_infra_key_file='ca_infra.key',
    ca_person_file='ca_person.pem',
    ca_person_key_file='ca_person.key',
)

TIMINGS = Histogram('http_requests_inprogress', 'HTTP request latency (seconds)')
REQUESTS = Counter('http_requests_total', 'Total HTTP Requests (count)', ['method', 'endpoint', 'status_code'])
IN_PROGRESS = Gauge('http_requests_inprogress', 'Number of in progress HTTP requests')

CERTIFICATE_SERVICE_REQUEST = dict(csr="pem csr base64 encoded")
CERTIFICATE_SERVICE_RESPONSE = dict(certificate="pem crt base64 encoded")
IDENTITIES_SERVICE_REQUEST = dict(identities=["identity1", "identity2"])
IDENTITIES_SERVICE_RESPONSE = [dict(certificate="pem crt base64 encoded", pkey="pem pkey base64 encoded"),
                               dict(certificate="pem crt base64 encoded", pkey="pem pkey base64 encoded")]
CONTENT_TYPE = "application/json"

CRL_DISTRIBUTION_POINTS = 'URI:http://dlp-pki-dev.G2N-Linky-Paris.gate-noe.enedis.fr:8080/crl'

TIMER = 0

app = Flask(__name__)

ca_infra_cert = None
ca_infra_key = None
ca_infra_edf_cert = None
ca_infra_edf_key = None
ca_person_cert = None
ca_person_key = None
ca_person_enedis_cert = None
ca_person_enedis_key = None


def shutdown_server():
    func = request.environ.get('werkzeug.server.shutdown')
    if func is None:
        raise RuntimeError('Not running with the Werkzeug Server')
    func()


def merge_dicts(*dict_args):
    result = {}
    for dictionary in dict_args:
        if isinstance(dictionary, dict):
            result.update(dictionary)
    return result


def load_ca_cert(ca_file):
    with open(ca_file, 'r') as f:
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
    return cert


def load_ca_private_key(private_key_file, passphrase=None):
    with open(private_key_file, 'r') as f:
        if passphrase:
            key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read(), passphrase)
        else:
            key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())
    return key


def get_certificate(csr_pem, personne=False):
    if personne:
        ca = ca_person_cert
        ca_key = ca_person_key
        crl = CRL_DISTRIBUTION_POINTS + '/ac_personne'
    else:
        ca = ca_infra_cert
        ca_key = ca_infra_key
        crl = CRL_DISTRIBUTION_POINTS + '/ac_infra'
    csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, csr_pem)
    cert = crypto.X509()
    cert.get_subject().C = ca.get_subject().C
    cert.get_subject().O = ca.get_subject().O
    cert.get_subject().OU = ca.get_subject().OU
    cert.get_subject().CN = csr.get_subject().CN

    if personne:
        cert.get_subject().UID = csr.get_subject().CN
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365*24*60*60*50)
    cert.set_version(2)

    md5_hash = hashlib.md5()
    md5_hash.update(csr.get_subject().CN)
    serial = int(md5_hash.hexdigest(), 36)
    cert.set_serial_number(serial)

    cert.set_issuer(ca.get_subject())
    cert.set_pubkey(csr.get_pubkey())
    extensions = [
        crypto.X509Extension('subjectKeyIdentifier', False, 'hash', subject=cert),
        crypto.X509Extension('authorityKeyIdentifier', False, 'keyid', issuer=ca),
        crypto.X509Extension('crlDistributionPoints', False, crl),
        # crypto.X509Extension('certificatePolicies', False, '1.3.6.1.5.5.7.5'),
        crypto.X509Extension('keyUsage', True, 'digitalSignature,keyEncipherment'),
        crypto.X509Extension('extendedKeyUsage', False, 'serverAuth,clientAuth')
    ]
    cert.add_extensions(extensions)
    cert.add_extensions(csr.get_extensions())
    cert.sign(ca_key, "sha256")

    return cert


def output_cert(cert):
    return dict(certificate=base64.b64encode(crypto.dump_certificate(crypto.FILETYPE_PEM, cert)))


def gen_pkey_req(identity):
    pkey = crypto.PKey()
    pkey.generate_key(crypto.TYPE_RSA, 2048)
    req = crypto.X509Req()
    req.get_subject().C = ca_infra_cert.get_subject().C
    req.get_subject().O = ca_infra_cert.get_subject().O
    req.get_subject().OU = ca_infra_cert.get_subject().OU
    req.get_subject().CN = identity
    req.set_pubkey(pkey)
    req.sign(pkey, "sha256")
    return crypto.dump_certificate_request(crypto.FILETYPE_PEM, req), crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey)


def get_certs_for_identities(identities):
    result = []
    for identity in identities:
        csr, pkey = gen_pkey_req(identity)
        pkey_b64 = dict(pkey=base64.b64encode(pkey))
        result.append(dict(output_cert(get_certificate(csr)), **pkey_b64))
    return result


def gen_pkcs12(name, cert, pkey):
    pkcs12 = crypto.PKCS12()
    pkcs12.set_certificate(cert)
    pkcs12.set_privatekey(pkey)
    pkcs12.set_friendlyname(name)
    return pkcs12.export(maciter=2048)


def gen_crl(cert, key, format_crl, serials=[]):
    crl = crypto.CRL()
    for s in serials:
        r = crypto.Revoked()
        r.set_reason('keyCompromise')
        r.set_rev_date('19700101000000Z')
        r.set_serial(s)
        crl.add_revoked(r)
    if format_crl == 'pem':
        format_crl = crypto.FILETYPE_PEM
    else:
        format_crl = crypto.FILETYPE_ASN1
    crl.set_version(1)
    crl.sign(cert, key, 'sha256')
    return crl.export(cert, key, format_crl, 18250, b'sha256')


@app.route('/version', methods=['GET'])
def version():
    return VERSION, 200


@app.route('/certificate', methods=['GET'])
def help_certificate():
    return render_template('help.html', title="/certificate",
                           contenttype=CONTENT_TYPE,
                           method='POST',
                           options='format=[json,value,pem]',
                           request=json.dumps(CERTIFICATE_SERVICE_REQUEST, indent=4, sort_keys=True),
                           response=json.dumps(CERTIFICATE_SERVICE_RESPONSE, indent=4, sort_keys=True))


@app.route('/identity', methods=['GET'])
def help_identity():
    return render_template('help.html', title="/identity/{identity}",
                           contenttype='N/A',
                           method='GET',
                           options='N/A',
                           request='N/A',
                           response='private key + certificat (format PEM)')


@app.route('/person', methods=['GET'])
def help_person():
    return render_template('help.html', title="/person/{uid}",
                           contenttype='N/A',
                           method='GET',
                           options='N/A',
                           request='N/A',
                           response='private key + certificat (format PEM)')


@app.route('/identities', methods=['GET'])
def help_identities():
    return render_template('help.html', title="/identities",
                           contenttype=CONTENT_TYPE,
                           method='POST',
                           options='format=[json,value,pem]',
                           request=json.dumps(IDENTITIES_SERVICE_REQUEST, indent=4, sort_keys=True),
                           response=json.dumps(IDENTITIES_SERVICE_RESPONSE, indent=4, sort_keys=True))


@app.route('/identity/<identity>', methods=['GET'])
@IN_PROGRESS.track_inprogress()
@TIMINGS.time()
def route_identity(identity):
    csr, pkey = gen_pkey_req(identity)
    cert = output_cert(get_certificate(csr))
    REQUESTS.labels(method='GET', endpoint="/identity", status_code=200).inc()
    return "\n".join([pkey, base64.b64decode(cert['certificate'])]), 200


@app.route('/person/<uid>', methods=['GET'])
def route_person(uid):
    csr, pkey = gen_pkey_req(uid)
    cert = get_certificate(csr, True)
    if request.args.get('format') == 'pkcs12':
        return base64.b64encode(gen_pkcs12(bytes(uid), cert, crypto.load_privatekey(crypto.FILETYPE_PEM, pkey))), 200
    else:
        return "\n".join([pkey, base64.b64decode(output_cert(cert)['certificate'])]), 200


@app.route('/certificate', methods=['POST'])
def route_certificate():
    if not request.json or 'csr' not in request.json:
        response = dict(error="Bad request",
                        request=dict(ContentType=CONTENT_TYPE, resquest=CERTIFICATE_SERVICE_REQUEST),
                        response=CERTIFICATE_SERVICE_RESPONSE)
        abort(make_response(jsonify(response), 400))
    csr_pem = base64.b64decode(request.json['csr'])
    certificate = output_cert(get_certificate(csr_pem))
    if request.args.get('format') == 'value':
        return certificate['certificate'], 201
    elif request.args.get('format') == 'pem':
        return base64.b64decode(certificate['certificate']), 201
    else:
        return jsonify(certificate), 201


@app.route('/identities', methods=['POST'])
def route_identities():
    if not request.json or 'identities' not in request.json:
        response = dict(error="Bad request",
                        request=dict(ContentType=CONTENT_TYPE, resquest=IDENTITIES_SERVICE_REQUEST),
                        response=IDENTITIES_SERVICE_RESPONSE)
        abort(make_response(jsonify(response), 400))
    identities = request.json['identities']
    certs = get_certs_for_identities(identities)
    if request.args.get('format') == 'value':
        l = [[cert['certificate'], cert['pkey']] for cert in certs]
        return "\n".join([item for sublist in l for item in sublist]), 201
    elif request.args.get('format') == 'pem':
        l = [[cert['certificate'], cert['pkey']] for cert in certs]
        return "\n".join([base64.b64decode(item) for sublist in l for item in sublist]), 201
    else:
        return jsonify(certs), 201


def get_crl(ca, key):
    b64 = True
    if request.args.get('format') == 'pem':
        format_crl = 'pem'
    elif request.args.get('format') == 'raw':
        format_crl = 'der'
        b64 = False
    else:
        format_crl = 'der'
    crl = gen_crl(ca, key, format_crl)
    if b64:
        crl = base64.b64encode(crl)
    return crl


@app.route('/crl/ac_infra', methods=['GET'])
def route_crl_infra():
    return get_crl(ca_infra_cert, ca_infra_key), 200


@app.route('/crl/ac_personnes', methods=['GET'])
def route_crl_person():
    return get_crl(ca_person_cert, ca_person_key), 200


@app.route('/crl/ac_infrastructure_erdf.crl', methods=['GET'])
@app.route('/crl-edf/crl/ac_infrastructure_erdf.crl', methods=['GET'])
def route_ac_infrastructure_erdf():
    return gen_crl(ca_infra_cert, ca_infra_key, 'der', ['0C6AFACB6B71BC8140AEF1BC5C5CDA0FD02D4C99E8']), 200


@app.route('/crl/ac_infrastructure_edf.crl', methods=['GET'])
@app.route('/crl-edf/crl/ac_infrastructure_edf.crl', methods=['GET'])
def route_ac_infrastructure_edf():
    return gen_crl(ca_infra_edf_cert, ca_infra_edf_key, 'der', ['0C6AFACB6B71BC8140AEF1BC5C5CDA0FD02D4C99E8']), 200


@app.route('/crl/ac_infrastructure_enedis.crl', methods=['GET'])
@app.route('/crl-edf/crl/ac_infrastructure_enedis.crl', methods=['GET'])
def route_ac_infrastructure_enedis():
    return gen_crl(ca_infra_cert, ca_infra_key, 'der', ['0C6AFACB6B71BC8140AEF1BC5C5CDA0FD02D4C99E8']), 200


@app.route('/crl/ac_personnes_erdf.crl', methods=['GET'])
def route_ac_personnes_erdf():
    return gen_crl(ca_person_cert, ca_person_key, 'der', ['0C6AFACB6B71BC8140AEF1BC5C5CDA0FD02D4C99E8']), 200


@app.route('/crl/ac_personnes_enedis.crl', methods=['GET'])
def route_ac_personnes_enedis():
    return gen_crl(ca_person_enedis_cert, ca_person_enedis_key, 'der', ['0C6AFACB6B71BC8140AEF1BC5C5CDA0FD02D4C99E8']), 200


@app.route('/shutdown', methods=['POST'])
def shutdown():
    shutdown_server()
    return 'Server shutting down...'


@app.route('/healthz')
def healthz():
    time.sleep(TIMER)
    return 'ok', 200


@app.route('/freeze/<timer>', methods=['GET'])
def freeze(timer):
    global TIMER
    TIMER = int(timer)
    return 'New timer : {timer}'.format(timer=TIMER), 200


@app.route('/timer', methods=['GET'])
def timer():
    return 'Timer : {timer}'.format(timer=TIMER), 200


@app.route('/metrics')
def metrics():
    return generate_latest(REGISTRY)


@app.route('/')
def root():
    return app.send_static_file('index.html')


def run(param_config=None):
    global ca_infra_cert
    global ca_infra_key
    global ca_infra_edf_cert
    global ca_infra_edf_key
    global ca_person_cert
    global ca_person_key
    global ca_person_enedis_cert
    global ca_person_enedis_key
    global TIMER
    run_config = merge_dicts(DEFAULT_CONFIG, param_config)
    ca_infra_cert = load_ca_cert(run_config.get('ca_infra_file'))
    ca_infra_key = load_ca_private_key(run_config.get('ca_infra_key_file'))
    ca_person_cert = load_ca_cert(run_config.get('ca_infra_file'))
    ca_person_key = load_ca_private_key(run_config.get('ca_infra_key_file'))
    ca_person_enedis_cert = load_ca_cert(run_config.get('ca_infra_file'))
    ca_person_enedis_key = load_ca_private_key(run_config.get('ca_infra_key_file'))
    ca_infra_edf_cert = load_ca_cert(run_config.get('ca_infra_edf_file'))
    ca_infra_edf_key = load_ca_private_key(run_config.get('ca_infra_edf_key_file'))
    app.run(run_config.get('host'), run_config.get('port'))
    TIMER = 0


if __name__ == "__main__":
    config = dict(ca_infra_file=os.environ.get('DLPPKIDEV_CA_INFRA_FILE', None),
                  ca_infra_key_file=os.environ.get('DLPPKIDEV_CA_INFRA_KEY_FILE', None),
                  ca_person_file=os.environ.get('DLPPKIDEV_CA_PERSON_FILE', None),
                  ca_person_key_file=os.environ.get('DLPPKIDEV_CA_PERSON_KEY_FILE', None),
                  ca_infra_edf_file=os.environ.get('DLPPKIDEV_CA_INFRA_FILE', None),
                  ca_infra_edf_key_file=os.environ.get('DLPPKIDEV_CA_INFRA_KEY_FILE', None))
    run(dict((k, v) for k, v in config.iteritems() if v))
