import test from "ava";

import { connect } from "../index.js";

test("connection failed without auth", async (t) => {
  if (process.platform !== "darwin" && process.platform !== "win32") {
    await t.throwsAsync(() => connect("github.com:22"));
  } else {
    await t.notThrowsAsync(() => connect("github.com:22"));
  }
});
