# grand-hash-auto
Automation fun with Kali Pass-The-Hash toolkit

# gha-win.py
Interactive pth-winexe bruteforcer. All the hashes!

### Requirements
* Python 3.5+ (guaranteed)
* May support 3.3+ (hack yourself)
* Python 2.x is a no-no (because reasons)


### Usage

```
chmod +x gha-win.py
./gha-win.py -h
```
or

```
Read the source, Luke!
```

Tip: `./gha-win.py IP --prefer IP --force-login --dns DNS_IP` will spawn interactive shell on the IP machine provided you have hash for it in the file. `--dns` can be omitted if section names are hostnames (use `--prefer HOSTNAME` instead of `--prefer IP` in this case)

### File with hashes

1. **#** indicates start of the machine section. Section name should be IP or hostname

2. For groups with IP names reverse DNS lookup is performed if `--dns` is set to valid IP. Doesn't perform check for whether the supplied IP is an actual DNS server. See `-h` for more.

3. Group of hashes separated with blank lines are assigned to `NONAME` machine

Example:

```
# bank
FilthyRich:5432:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::: (1)

# 127.0.0.1
Administrator:9999:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::: (2)

SupaHakka:1337:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::: (3)
```

### Interactivity & loops
Although it is possible to use inside (bash) loop, `gha-win.py` will drop into an interactive shell if matching hash is found. Use `exit` to break out of the shell and then choose whether you want to continue bruteforce attempts.

# Contributing
Scripts were written just for fun and may contain bugs. If you feel like it, submit pull request.