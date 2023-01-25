# `@napi-rs/ssh`

![CI](https://github.com/Brooooooklyn/ssh/workflows/CI/badge.svg)
[![install size](https://packagephobia.com/badge?p=@napi-rs/ssh)](https://packagephobia.com/result?p=@napi-rs/ssh)
[![Downloads](https://img.shields.io/npm/dm/@napi-rs/ssh.svg?sanitize=true)](https://npmcharts.com/compare/@napi-rs/ssh?minimal=true)

> 🚀 Help me to become a full-time open-source developer by [sponsoring me on Github](https://github.com/sponsors/Brooooooklyn)

## Usage

```js
import { connect, checkKnownHosts } from '@napi-rs/ssh'

const host = '192.168.65.3'
const port = 22

const client = await connect(`${host}:${port}`, {
  checkServerKey: (key) => {
    return checkKnownHosts(host, port, key)
  }
})

await client.authenticateKeyPair('lyn')

const { status, output } = await client.exec('ls -la')
console.log(status, output.toString('utf8'))

// 0 total 292
// drwxr-x--- 11 lyn  lyn    4096 Jan 23 06:39 .
// drwxr-xr-x  3 root root   4096 Jan 19 06:50 ..
// -rw-------  1 lyn  lyn    2065 Jan 20 03:11 .bash_history
// -rw-r--r--  1 lyn  lyn     220 Jan  6  2022 .bash_logout
// -rw-r--r--  1 lyn  lyn    3792 Jan 19 09:11 .bashrc
// drwx------  5 lyn  lyn    4096 Jan 20 03:28 .cache
// -rw-r--r--  1 lyn  lyn     828 Jan 19 09:11 .profile
// drwx------  2 lyn  lyn    4096 Jan 19 09:07 .ssh
// drwxrwxr-x  3 lyn  lyn    4096 Jan 19 09:59 .yarn
// -rw-r--r--  1 lyn  lyn    3922 Jan 20 03:30 .zshrc
```
