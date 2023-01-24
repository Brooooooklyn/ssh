import test from 'ava'

import { connect } from '../index.js'

test('connection failed without auth', async (t) => {
  await t.throwsAsync(() => connect('github.com:22'))
})
