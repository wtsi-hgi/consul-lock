[![Build Status](https://travis-ci.org/wtsi-hgi/consul-lock.svg?branch=master)](https://travis-ci.org/wtsi-hgi/consul-lock)
[![codecov](https://codecov.io/gh/wtsi-hgi/consul-lock/branch/master/graph/badge.svg)](https://codecov.io/gh/wtsi-hgi/consul-lock)

# Consul Lock
_CLI and Python interface for easily managing Consul locks_


## About
- JSON output
- Exit codes

## Installation
Prerequisites:
- python >= 3.6

The tool can be installed from PyPi:
```bash
pip install consullock
```

Bleeding edge versions can be installed directly from GitHub:
```bash
pip install git+https://github.com/wtsi-hgi/consul-lock.git@master#egg=consullock
```


## Usage
### CLI
#### Setup
Set environment variables:
```bash
export CONSUL_HTTP_ADDR=consul.example.com:8500
export CONSUL_HTTP_TOKEN=token
```

#### Usage
##### General
```
usage: consul-lock [-h] [-v] {unlock,lock} ...

Tool to use locks in Consul

positional arguments:
  {unlock,lock}  action
    unlock       release a lock
    lock         acquire a lock

optional arguments:
  -h, --help     show this help message and exit
  -v             increase the level of log verbosity (add multiple increase
                 further)
```

##### Locking
```
usage: consul-lock lock [-h] [--session-ttl SESSION_TTL] [--non-blocking]
                        [--timeout TIMEOUT]
                        key

positional arguments:
  key                   the lock identifier

optional arguments:
  -h, --help            show this help message and exit
  --session-ttl SESSION_TTL
                        time to live (ttl) in seconds of the session that will
                        be created to hold the lock. Must be between 10s and
                        86400s (inclusive). If set to 0, the session will not
                        expire
  --non-blocking        do not block if cannot lock straight away
  --timeout TIMEOUT     give up trying to acquire the key after this many
                        seconds (where 0 is never)
```

##### Unlocking              
```
usage: consul-lock unlock [-h] [-r] key

positional arguments:
  key         the lock identifier

optional arguments:
  -h, --help  show this help message and exit
  -r          Whether the key should be treated as a regular expression and to
              release all matching locks
```


#### Examples
Block until acquires lock with key "my/lock", which will expire after 10 minutes:
```
$ consul-lock lock --session-ttl=600 my/lock
{"created": "2017-11-30T14:55:49.322108", "key": "my/lock", "session": "9b92744f-f1a9-db12-7873-ad44af5ae224"}
$ echo $?
0 
```

Try to acquire already locked "my/lock" but do not block:
```
$ consul-lock lock --non-blocking my/lock
null
Unable to acquire lock: my/lock
$ echo $?
100
```
(where `null` is the JSON output, written to stdout)

Unlock lock:
```bash
$ consul-lock unlock my/lock
```

### Python
```python
# TODO
```


## Alternatives
- [alaa/consul-lock](https://github.com/alaa/consul-lock) - Go tool with CLI where the user has to deal with sessions.
- [fidian/consul-locker](https://github.com/fidian/consul-locker) - bash script that locks, executes and then releases.
- [KurToMe/python-consul-lock](https://github.com/KurToMe/python-consul-lock) - unmaintained Python lock interface with 
with questionable configuration practice.