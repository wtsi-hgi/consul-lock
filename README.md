[![Build Status](https://travis-ci.org/wtsi-hgi/consul-lock.svg?branch=master)](https://travis-ci.org/wtsi-hgi/consul-lock)
[![codecov](https://codecov.io/gh/wtsi-hgi/consul-lock/branch/master/graph/badge.svg)](https://codecov.io/gh/wtsi-hgi/consul-lock)
[![PyPI version](https://badge.fury.io/py/consullock.svg)](https://badge.fury.io/py/consullock)

# Consul Lock
_CLI and Python interface for easily managing Consul locks_


## About
- CLI & Python interface:
    - Acquire and release a lock.
    - Execute shell whilst holding a lock (releasing on exit).
    - Set TTL of the session that acquires a lock.
    - Blocking and non-blocking locking.
    - Lock acquire timeouts.
    - Add extra metadata to lock information (useful for monitoring who is holding locks).
    - Specify lock event listeners to be fired before lock acquire is attempted and if unable to acquire locked lock.
- CLI:
    - Release multiple locks with keys that match regular expression.
    - Meaningful exit codes (see `configuration.py` for details).
    - JSON output on stdout.
    - Add extra verbosity on stderr with `-vv`.
- Python interface:
    - Release multiple locks.
    - Find and release multiple locks with keys that match regular expression.
    - Type hinting.


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

#### General
```
usage: consullock [-h] [-v] {unlock,lock,execute} ...

Tool to use locks in Consul (v4.2.0)

positional arguments:
  {unlock,lock,execute}
                        action
    unlock              release a lock
    lock                acquire a lock
    execute             call executable whilst holding lock

optional arguments:
  -h, --help            show this help message and exit
  -v                    increase the level of log verbosity (add multiple
                        increase further)
```

#### Locking
```
usage: consullock lock [-h] [--session-ttl SESSION_TTL] [--non-blocking]
                       [--timeout TIMEOUT] [--metadata METADATA]
                       [--on-before-lock ON_BEFORE_LOCK [ON_BEFORE_LOCK ...]]
                       [--on-already-locked ON_ALREADY_LOCKED [ON_ALREADY_LOCKED ...]]
                       [-i I]
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
  --metadata METADATA   additional metadata to add to the lock information
                        (will be converted to JSON)
  --on-before-lock ON_BEFORE_LOCK [ON_BEFORE_LOCK ...]
                        path to executable that is to be called before an
                        attempt is made to acquire a lock, where the lock key
                        is passed as the first argument. Any failures of this
                        executable are ignored
  --on-already-locked ON_ALREADY_LOCKED [ON_ALREADY_LOCKED ...]
                        path to executable that is to be called after an
                        attempt has been made to acquire a lock but failed due
                        to the lock already been taken, where the lock key is
                        passed as the first argument. Any failures of this
                        executable are ignored
  -i I                  number of seconds between polls to acquire a locked
                        lock
```

#### Unlocking              
```
usage: consullock unlock [-h] [-r] key

positional arguments:
  key         the lock identifier

optional arguments:
  -h, --help  show this help message and exit
  -r          whether the key should be treated as a regular expression and to
              release all matching locks
```

#### Executing with lock
```
usage: consullock execute [-h] [--session-ttl SESSION_TTL] [--non-blocking]
                          [--timeout TIMEOUT] [--metadata METADATA]
                          [--on-before-lock ON_BEFORE_LOCK [ON_BEFORE_LOCK ...]]
                          [--on-already-locked ON_ALREADY_LOCKED [ON_ALREADY_LOCKED ...]]
                          [-i I]
                          key executable

positional arguments:
  key                   the lock identifier
  executable            to execute in shell

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
  --metadata METADATA   additional metadata to add to the lock information
                        (will be converted to JSON)
  --on-before-lock ON_BEFORE_LOCK [ON_BEFORE_LOCK ...]
                        path to executable that is to be called before an
                        attempt is made to acquire a lock, where the lock key
                        is passed as the first argument. Any failures of this
                        executable are ignored
  --on-already-locked ON_ALREADY_LOCKED [ON_ALREADY_LOCKED ...]
                        path to executable that is to be called after an
                        attempt has been made to acquire a lock but failed due
                        to the lock already been taken, where the lock key is
                        passed as the first argument. Any failures of this
                        executable are ignored
  -i I                  number of seconds between polls to acquire a locked
                        lock
```

#### Examples
##### Acquire lock
Block until acquires lock with key "my/lock", which will expire after 10 minutes:
```
$ consul-lock lock --session-ttl=600 my/lock
{"created": "2017-11-30T14:55:49.322108", "key": "my/lock", "secondsToLock": 2.6241003070026636e-05, "session": "9b92744f-f1a9-db12-7873-ad44af5ae224"}
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


##### Add metadata to lock
```
$ consul-lock lock --metadata={"testing": 123} my/lock
{"created": "2017-12-05T12:26:13.717995", "key": "my/lock", "metadata": {"testing": 123}, "secondsToLock": 4.327880731027108, "session": "6ad662de-6e0c-8e0f-d92c-5fface60c49b"}
```


##### Acquire lock with event listeners
```
$ consul-lock lock --on-before-lock=./my-before-script.sh --on-already-locked=./my-locked-script.sh my/lock
{"created": "2017-12-07T13:02:06.773088", "key": "my/lock", "secondsToLock": 1.349498052150011e-05, "session": "459266be-2a85-464e-aa08-eda97613a29c"}
```
_Note: if specifying event listeners in the form `--x y`, you will need to explicitly declare the end of the command 
options with a double dash, e.g. `consul-lock lock --on-before-lock ./my-before-script.sh -- my/lock`._


##### Unlock lock
```bash
$ consul-lock unlock my/lock
["my/lock"]
$ echo $?
0
```


##### Execute shell with lock
```bash
$ consul-lock execute my/lock ./my-executable
I am printed in "my-executable"
```
_Note: the return code is the result of the executable_


### Python
```python
from typing import Dict
from consullock.configuration import get_consul_configuration_from_environment
from consullock.managers import ConsulLockManager
from consullock.models import ConsulLockInformation

# Instantiate lock manager
lock_manager = ConsulLockManager(
    consul_configuration=get_consul_configuration_from_environment(),
    session_ttl_in_seconds=3600)
# Note: if the Consul configuration is not specified explicitly, an attempt to gather it from environmental variables 
# will be made (see: https://www.consul.io/docs/commands/index.html#environment-variables).

# Use lock in context
with lock_manager.acquire("my/lock"):
    do_things_holding_lock()

# Get lock
lock = lock_manager.acquire("my/lock", timeout=60, blocking=True, metadata="testing")

# Find lock associated to a given key
lock = lock_manager.find("my/lock")

# Find locks that match a regex
locks = lock_manager.find_regex("my/.*")  # type: Dict[str, Optional[ConsulLockInformation]]

# Release single lock
lock_manager.release("my/lock")

# Release many locks
lock_manager.release_all("my/lock-1", "my/lock-2", "my/lock-3")

# Release locks with key matching regex
lock_manager.release_regex("my/.*")

# Execute shell whilst holding lock (note: use context manager if executing Python!)
lock_manager.execute("my/lock", "echo Hello World")
```


## Development
### Tests
Prerequisites:
- Docker (used to start Consul instances)

Install the test requirements:
```
pip install -r test_requirements.txt
```

Run tests with:
```
PYTHONPATH=. python -m unittest discover -v -s consullock/tests
```


## Alternatives
- [alaa/consul-lock](https://github.com/alaa/consul-lock) - Go tool with CLI where the user has to deal with sessions.
- [fidian/consul-locker](https://github.com/fidian/consul-locker) - bash script that locks, executes and then releases.
- [KurToMe/python-consul-lock](https://github.com/KurToMe/python-consul-lock) - unmaintained Python lock interface with 
with questionable configuration.