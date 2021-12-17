#!/usr/bin/env python3

import base64
import contextlib
import getpass
import json
import os
import re
import signal
import subprocess
import sys
import urllib.parse

import click
import lxml.etree
import requests

try:
    import pyotp
except ImportError:
    pyotp = None


def check(r: requests.Response):
    r.raise_for_status()
    return r


def extract_form(html: str):
    form = lxml.etree.fromstring(html, lxml.etree.HTMLParser()).find('.//form')
    return (
        form.attrib['action'],
        {inp.attrib['name']: inp.attrib['value'] for inp in form.findall('input')},
    )


def prelogin(s: requests.Session, gateway: str):
    r = check(s.post('https://{}/ssl-vpn/prelogin.esp'.format(gateway)))
    saml_req_html = base64.b64decode(
        lxml.etree.fromstring(r.content).find('saml-request').text
    )
    saml_req_url, saml_req_data = extract_form(saml_req_html)
    assert 'SAMLRequest' in saml_req_data
    return saml_req_url + '?' + urllib.parse.urlencode(saml_req_data)


def post_json(s: requests.Session, url: str, data: object):
    r = check(
        s.post(url, data=json.dumps(data), headers={'Content-Type': 'application/json'})
    )
    return r.json()


def okta_auth(
    s: requests.Session, domain: str, username: str, password: str, totp_key: str | None
):
    r = post_json(
        s,
        'https://{}/api/v1/authn'.format(domain),
        {'username': username, 'password': password},
    )

    if r['status'] == 'MFA_REQUIRED':

        def priority(factor: dict[str, str]):
            return {'token:software:totp': 2 if totp_key is None else 0, 'push': 1}.get(
                factor['factorType'], 2
            )

        for factor in sorted(r['_embedded']['factors'], key=priority):
            if factor['factorType'] == 'push':
                url = factor['_links']['verify']['href']
                while True:
                    r = post_json(s, url, {'stateToken': r['stateToken']})
                    if r['status'] != 'MFA_CHALLENGE':
                        break
                    assert r['factorResult'] == 'WAITING'
                break
            if factor['factorType'] == 'sms':
                url = factor['_links']['verify']['href']
                r = post_json(s, url, {'stateToken': r['stateToken']})
                assert r['status'] == 'MFA_CHALLENGE'
                code = input('SMS code: ')
                r = post_json(s, url, {'stateToken': r['stateToken'], 'passCode': code})
                break
            if re.match('token(?::|$)', factor['factorType']):
                url = factor['_links']['verify']['href']
                r = post_json(s, url, {'stateToken': r['stateToken']})
                assert r['status'] == 'MFA_CHALLENGE'
                if (factor['factorType'] == 'token:software:totp') and (
                    totp_key is not None
                ):
                    code = pyotp.TOTP(totp_key).now()
                else:
                    code = input(
                        'One-time code for {} ({}): '.format(
                            factor['provider'], factor['vendorName']
                        )
                    )
                r = post_json(s, url, {'stateToken': r['stateToken'], 'passCode': code})
                break
        else:
            raise Exception('No supported authentication factors')

    assert r['status'] == 'SUCCESS'
    return r['sessionToken']


def okta_saml(
    s: requests.Session,
    saml_req_url: str,
    username: str,
    password: str,
    totp_key: str | None,
):
    domain = urllib.parse.urlparse(saml_req_url).netloc

    # Just to set DT cookie
    check(s.get(saml_req_url))

    token = okta_auth(s, domain, username, password, totp_key)

    r = check(
        s.get(
            'https://{}/login/sessionCookieRedirect'.format(domain),
            params={'token': token, 'redirectUrl': saml_req_url},
        )
    )
    saml_resp_url, saml_resp_data = extract_form(r.content)
    assert 'SAMLResponse' in saml_resp_data
    return saml_resp_url, saml_resp_data


def complete_saml(
    s: requests.Session, saml_resp_url: str, saml_resp_data: dict[str, object]
):
    r = check(s.post(saml_resp_url, data=saml_resp_data))
    return r.headers['saml-username'], r.headers['prelogin-cookie']


@contextlib.contextmanager
def signal_mask(how: int, mask: set[signal.Signals]):
    old_mask = signal.pthread_sigmask(how, mask)
    try:
        yield old_mask
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)


@contextlib.contextmanager
def signal_handler(num: signal.Signals, handler: callable):
    old_handler = signal.signal(num, handler)
    try:
        yield old_handler
    finally:
        signal.signal(num, old_handler)


@contextlib.contextmanager
def popen_forward_sigterm(args: list[str], *, stdin=None):
    with signal_mask(signal.SIG_BLOCK, {signal.SIGTERM}) as old_mask:
        with subprocess.Popen(
            args,
            stdin=stdin,
            preexec_fn=lambda: signal.pthread_sigmask(signal.SIG_SETMASK, old_mask),
        ) as p:
            with signal_handler(signal.SIGTERM, lambda *args: p.terminate()):
                with signal_mask(signal.SIG_SETMASK, old_mask):
                    yield p
                    if p.stdin:
                        p.stdin.close()
                    os.waitid(os.P_PID, p.pid, os.WEXITED | os.WNOWAIT)


@click.command()
@click.argument('gateway')
@click.argument('openconnect-args', nargs=-1)
@click.option('--username')
@click.option('--password')
@click.option('--totp-key')
@click.option('--sudo/--no-sudo', default=False)
def main(
    gateway: str,
    openconnect_args: list[str],
    username: str | None,
    password: str | None,
    totp_key: str | None,
    sudo: bool,
):
    if (totp_key is not None) and (pyotp is None):
        print('--totp-key requires pyotp!', file=sys.stderr)
        sys.exit(1)

    if username is None:
        username = input('Username: ')
    if password is None:
        password = getpass.getpass()

    with requests.Session() as s:
        saml_req_url = prelogin(s, gateway)
        saml_resp_url, saml_resp_data = okta_saml(
            s, saml_req_url, username, password, totp_key
        )
        saml_username, prelogin_cookie = complete_saml(s, saml_resp_url, saml_resp_data)

    subprocess_args = [
        'openconnect',
        gateway,
        '--protocol=gp',
        '--user=' + saml_username,
        '--usergroup=gateway:prelogin-cookie',
        '--passwd-on-stdin',
    ] + list(openconnect_args)

    if sudo:
        subprocess_args = ['sudo'] + subprocess_args

    with popen_forward_sigterm(subprocess_args, stdin=subprocess.PIPE) as p:
        p.stdin.write(prelogin_cookie.encode())
    sys.exit(p.returncode)


if __name__ == '__main__':
    main()
