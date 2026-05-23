"""QA-FIX-10 unit tests for auditd_enrich.lua.

Exercises the enrich_ecs Lua function with mock merged records that mimic the
output of auditd_merge.lua. Verifies fixes for:
  #1 user.name fallback for USER_*/CRED_* events
  #2 event.outcome fallback to cred_*_res
  #3 auditd.session fallback to cred_*_ses
  #4 syscall_44/46/119/126 -> sendto/sendmsg/setresgid/setregid
"""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

import lupa

SCRIPT_DIR = Path(__file__).resolve().parent.parent / "agents" / "configs" / "fluent-bit" / "scripts"


def make_lua():
    """Build a Lua runtime with a stubbed proc_common module pre-loaded."""
    lua = lupa.LuaRuntime(unpack_returned_tuples=True)
    # Stub proc_common: bypass /proc and /etc/passwd. Tests don't depend on
    # parent process resolution; we just need stable functions.
    stub = r"""
    local M = {}
    function M.get_hostname() return "testhost" end
    function M.get_btime() return 1700000000 end
    function M.get_clk_tck() return 100 end
    function M.read_proc_start(pid) return nil end
    function M.resolve_start(pid) return nil end
    function M.resolve_name(pid) return nil end
    function M.resolve_cmdline(pid) return nil end
    function M.cache_put(pid, ts, force) end
    function M.cache_put_name(pid, n) end
    function M.cache_put_cmdline(pid, c) end
    function M.uid_to_name(uid) return nil end
    function M.short_id(s) return "deadbeefdeadbeef" end
    function M.make_session_id(host, ses) return "session-" .. tostring(ses) end
    function M.get_sessionid(pid) return nil end
    function M.to_iso(ts)
        if type(ts) == "number" then
            return os.date("!%Y-%m-%dT%H:%M:%S.000Z", ts)
        end
        return ts
    end
    package.loaded["proc_common"] = M
    """
    lua.execute(stub)

    enrich_src = (SCRIPT_DIR / "auditd_enrich.lua").read_text(encoding="utf-8")
    # The script does `package.path = _dir .. "?.lua;" ...` based on
    # debug.getinfo(1, "S").source. Under lupa loading via execute() the source
    # is "=(load)" so _dir is "". That is fine because we already injected
    # proc_common into package.loaded above.
    lua.execute(enrich_src)
    return lua


def make_record(lua, fields: dict):
    """Convert a plain Python dict to a Lua table.

    Nested dicts (e.g. _event_types) and lists (_execve_args / _paths) are
    converted recursively. This is what auditd_merge.lua hands to enrich_ecs.
    """
    def convert(v):
        if isinstance(v, dict):
            t = lua.table_from({})
            for k, vv in v.items():
                t[k] = convert(vv)
            return t
        if isinstance(v, list):
            t = lua.table_from({})
            for i, vv in enumerate(v, 1):
                t[i] = convert(vv)
            return t
        return v
    return convert(fields)


def call_enrich(lua, fields: dict) -> dict:
    rec = make_record(lua, fields)
    enrich = lua.globals().enrich_ecs
    _code, _ts, out = enrich("test.tag", 1700000123, rec)
    # Convert Lua table to plain dict for assertions
    result = {}
    for k, v in out.items():
        if lupa.lua_type(v) == "table":
            # represent nested tables as Python lists/dicts of primitives
            sub = {}
            for kk, vv in v.items():
                sub[kk] = vv
            # Lua tables-as-arrays: collapse to list if keys are 1..N integers
            if sub and all(isinstance(kk, int) for kk in sub.keys()):
                result[k] = [sub[i] for i in sorted(sub.keys())]
            else:
                result[k] = sub
        else:
            result[k] = v
    return result


class TestQAFix10(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lua = make_lua()

    # ---- #1 user.name fallback ----------------------------------------

    def test_user_name_from_uid_name_priority(self):
        """uid_name (kernel-resolved) wins over fallback chain."""
        out = call_enrich(self.lua, {
            "uid": "1000",
            "uid_name": "alice",
            "auid_name": "bob",
            "user_acct": "root",
            "_event_types": {"USER_ACCT": True},
        })
        self.assertEqual(out["user.name"], "alice")
        self.assertEqual(out.get("user.target.name"), "root")

    def test_user_name_fallback_to_auid_name(self):
        """No uid_name -> auid_name (requesting user)."""
        out = call_enrich(self.lua, {
            "auid": "1000",
            "auid_name": "installer",
            "user_acct": "root",
            "_event_types": {"USER_ACCT": True},
        })
        self.assertEqual(out["user.name"], "installer")

    def test_user_name_fallback_to_user_acct(self):
        """No uid_name/auid_name -> user_acct."""
        out = call_enrich(self.lua, {
            "user_acct": "alice",
            "_event_types": {"USER_ACCT": True},
        })
        self.assertEqual(out["user.name"], "alice")

    def test_user_name_fallback_to_cred_disp_acct(self):
        """CRED_DISP: kernel doesn't supply uid_name; cred_disp_acct is used."""
        out = call_enrich(self.lua, {
            "cred_disp_acct": "root",
            "cred_disp_res": "success",
            "cred_disp_ses": "5",
            "_event_types": {"CRED_DISP": True},
        })
        self.assertEqual(out["user.name"], "root")

    def test_user_name_fallback_to_cred_refr_acct(self):
        out = call_enrich(self.lua, {
            "cred_refr_acct": "alice",
            "_event_types": {"CRED_REFR": True},
        })
        self.assertEqual(out["user.name"], "alice")

    def test_user_name_fallback_to_cred_acq_acct(self):
        out = call_enrich(self.lua, {
            "cred_acq_acct": "root",
            "_event_types": {"CRED_ACQ": True},
        })
        self.assertEqual(out["user.name"], "root")

    # ---- #2 event.outcome fallback to cred_*_res ----------------------

    def test_outcome_from_cred_disp_res(self):
        out = call_enrich(self.lua, {
            "cred_disp_acct": "root",
            "cred_disp_res": "success",
            "_event_types": {"CRED_DISP": True},
        })
        self.assertEqual(out["event.outcome"], "success")

    def test_outcome_from_cred_refr_res_failure(self):
        out = call_enrich(self.lua, {
            "cred_refr_acct": "alice",
            "cred_refr_res": "failed",
            "_event_types": {"CRED_REFR": True},
        })
        self.assertEqual(out["event.outcome"], "failure")

    def test_outcome_from_cred_acq_res(self):
        out = call_enrich(self.lua, {
            "cred_acq_acct": "root",
            "cred_acq_res": "success",
            "_event_types": {"CRED_ACQ": True},
        })
        self.assertEqual(out["event.outcome"], "success")

    # ---- #3 auditd.session fallback to cred_*_ses ---------------------

    def test_session_from_cred_disp_ses(self):
        out = call_enrich(self.lua, {
            "cred_disp_acct": "root",
            "cred_disp_ses": "7",
            "_event_types": {"CRED_DISP": True},
        })
        self.assertEqual(out["auditd.session"], 7)

    def test_session_unset_value_ignored(self):
        """ses=4294967295 (kernel "unset") must be ignored."""
        out = call_enrich(self.lua, {
            "cred_disp_acct": "root",
            "cred_disp_ses": "4294967295",
            "_event_types": {"CRED_DISP": True},
        })
        self.assertNotIn("auditd.session", out)

    # ---- #4 syscall mapping --------------------------------------------

    def test_syscall_44_sendto(self):
        out = call_enrich(self.lua, {
            "syscall": "44",
            "pid": "100",
            "_event_types": {"SYSCALL": True},
        })
        self.assertEqual(out["event.action"], "sendto")
        self.assertEqual(out["auditd.data.syscall"], "sendto")
        self.assertEqual(out["event.category"], "network")
        self.assertEqual(out["event.type"], "info")

    def test_syscall_46_sendmsg(self):
        out = call_enrich(self.lua, {
            "syscall": "46",
            "pid": "100",
            "_event_types": {"SYSCALL": True},
        })
        self.assertEqual(out["event.action"], "sendmsg")
        self.assertEqual(out["event.category"], "network")

    def test_syscall_119_setresgid_iam(self):
        out = call_enrich(self.lua, {
            "syscall": "119",
            "pid": "100",
            "_event_types": {"SYSCALL": True},
        })
        self.assertEqual(out["event.action"], "setresgid")
        self.assertEqual(out["event.category"], "iam")
        self.assertEqual(out["event.type"], "change")

    def test_syscall_126_setregid_iam(self):
        out = call_enrich(self.lua, {
            "syscall": "126",
            "pid": "100",
            "_event_types": {"SYSCALL": True},
        })
        self.assertEqual(out["event.action"], "setregid")
        self.assertEqual(out["event.category"], "iam")

    def test_unknown_syscall_keeps_syscall_NNN(self):
        """Sanity: an unknown number still falls back to syscall_<num>."""
        out = call_enrich(self.lua, {
            "syscall": "9999",
            "pid": "100",
            "_event_types": {"SYSCALL": True},
        })
        self.assertEqual(out["event.action"], "syscall_9999")

    # ---- regression: existing flows still work -------------------------

    def test_user_acct_outcome_session_still_work(self):
        """USER_ACCT (user_* prefix) flow must continue to work."""
        out = call_enrich(self.lua, {
            "uid": "0",
            "uid_name": "root",
            "user_acct": "alice",
            "user_res": "success",
            "user_ses": "3",
            "_event_types": {"USER_ACCT": True},
        })
        self.assertEqual(out["user.name"], "root")           # uid_name wins
        self.assertEqual(out["user.target.name"], "alice")
        self.assertEqual(out["event.outcome"], "success")
        self.assertEqual(out["auditd.session"], 3)
        self.assertEqual(out["event.action"], "user_acct")

    def test_syscall_execve_unchanged(self):
        out = call_enrich(self.lua, {
            "syscall": "59",
            "pid": "100",
            "comm": "ls",
            "exe": "/bin/ls",
            "_event_types": {"SYSCALL": True, "EXECVE": True},
        })
        self.assertEqual(out["event.action"], "execve")
        self.assertEqual(out["event.category"], "process")
        self.assertEqual(out["event.type"], "start")

    def test_setuid_still_iam(self):
        out = call_enrich(self.lua, {
            "syscall": "105",
            "pid": "100",
            "_event_types": {"SYSCALL": True},
        })
        self.assertEqual(out["event.action"], "setuid")
        self.assertEqual(out["event.category"], "iam")

    def test_raw_fields_cleaned(self):
        """Raw user_/cred_/uid_name/auid_name fields must be removed at end."""
        out = call_enrich(self.lua, {
            "uid_name": "root",
            "auid_name": "alice",
            "user_acct": "bob",
            "user_res": "success",
            "user_ses": "1",
            "cred_disp_acct": "carol",
            "cred_disp_res": "success",
            "cred_disp_ses": "2",
            "_event_types": {"USER_ACCT": True},
        })
        for k in ["uid_name", "auid_name", "user_acct", "user_res", "user_ses",
                  "cred_disp_acct", "cred_disp_res", "cred_disp_ses"]:
            self.assertNotIn(k, out, f"raw field {k!r} should be cleaned")


if __name__ == "__main__":
    unittest.main(verbosity=2)
