import { connect, checkKnownHosts } from './index.js'

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
