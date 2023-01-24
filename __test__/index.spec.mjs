import test from 'ava'

import { connect } from '../index.js'

test('connection failed without auth', async (t) => {
  await t.notThrowsAsync(() => connect('github.com:22'))
})
