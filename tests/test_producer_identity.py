"""#29: preserve literal producer identity only in closed pure moves."""
import json
import unittest
from pinwash.engine import scan_pair
P, N, R = ".github/workflows/ci.yml", ".github/workflows/moved.yml", ".github/rulesets/main.json"
RS = json.dumps({"rules": [{"type": "required_status_checks", "parameters": {"required_status_checks": [{"context": "tripwire"}]}}]}).encode()
def wf(key="gate", run="python verify.py", extra=""):
    return ("on: [push, pull_request]\n" + extra + "jobs:\n  " + key + ":\n    name: tripwire\n    runs-on: ubuntu-latest\n    steps:\n      - run: " + run + "\n").encode()
def scan(b, h):
    return scan_pair({R: RS, **b}, {R: RS, **h}, base_label="b", head_label="h", env={"PINWASH_TODAY": "2026-10-14"})
def drops(r):
    return [f for f in r["findings"] if f["rule"] == "REQUIRED_CHECK_DROPPED"]
class ProducerIdentity(unittest.TestCase):
    def test_admission_requires_an_explicit_plain_literal_name(self):
        from pinwash.parse.gha import parse_workflow
        from pinwash.producer_identity import admissible, matches

        plain = parse_workflow(wf().decode())
        self.assertTrue(admissible(plain.jobs["gate"], plain.jobs))
        for raw in ("!tag tripwire", "*alias", "[tripwire]", "{name: tripwire}",
                    "|", ">", "%directive", "@name", "`name`", "&anchor tripwire",
                    "'tripwire'", '"tripwire"', "${{ inputs.name }}"):
            with self.subTest(raw=raw):
                body = wf().replace(b"name: tripwire", ("name: " + raw).encode())
                parsed = parse_workflow(body.decode())
                self.assertFalse(admissible(parsed.jobs["gate"], parsed.jobs))
                rekeyed = body.replace(b"  gate:\n", b"  verify:\n")
                self.assertEqual(matches({P: body}, {P: rekeyed}), {})
                self.assertEqual(matches({P: body}, {N: body}), {})

    def test_pure_rekey_with_literal_context_is_not_deleted(self):
        self.assertEqual(drops(scan({P: wf()}, {P: wf("verify")})), [])
    def test_identical_whole_file_move_is_not_deleted(self):
        self.assertEqual(drops(scan({P: wf()}, {N: wf()})), [])
    def test_same_name_gutted_decoy_does_not_hide_deletion(self):
        self.assertTrue(drops(scan({P: wf()}, {P: wf("verify", "true")})))
    def test_changed_top_level_execution_settings_do_not_match(self):
        self.assertTrue(drops(scan({P: wf()}, {N: wf(extra="permissions: {}\n")})))
    def test_dynamic_job_read_prevents_rekey(self):
        self.assertTrue(drops(scan({P: wf(run="echo $GITHUB_JOB")}, {P: wf("verify", "echo $GITHUB_JOB")})))
    def test_ambiguous_whole_file_destinations_do_not_match(self):
        self.assertTrue(drops(scan({P: wf()}, {N: wf(), ".github/workflows/also.yml": wf()})))
    def test_comment_like_run_bytes_are_not_discarded(self):
        self.assertTrue(drops(scan({P: wf(run="echo '# old'")}, {P: wf("verify", "echo '# new'")})))

    def test_script_filename_is_not_a_job_key_reference(self):
        self.assertEqual(drops(scan({P: wf(run="python verify.py")}, {P: wf("verify", "python verify.py")})), [])

    def test_direct_dependency_and_context_references_prevent_rekey(self):
        dependent = b"  helper:\n    name: helper\n    needs: gate\n    runs-on: ubuntu-latest\n    steps:\n      - run: check\n"
        self.assertTrue(drops(scan({P: wf() + dependent}, {P: wf("verify") + dependent})))
        for run in ("echo ${{ needs.gate.result }}", "echo ${{ needs['gate'].result }}",
                    "echo ${{ (needs).gate.result }}", "echo ${{ jobs [ 'gate' ].result }}",
                    "echo ${{ (( needs ) ) . gate.result }}"):
            with self.subTest(run=run):
                self.assertTrue(drops(scan({P: wf(run=run)}, {P: wf("verify", run)})))

    def test_unrelated_hyphenated_job_reference_does_not_prevent_rekey(self):
        rest = (b"  gate-other:\n    name: other\n    runs-on: ubuntu-latest\n    steps:\n      - run: check\n"
                b"  helper:\n    name: helper\n    needs: gate-other\n    runs-on: ubuntu-latest\n    steps:\n"
                b"      - run: echo ${{ needs.gate-other.result }}\n")
        self.assertEqual(drops(scan({P: wf() + rest}, {P: wf("verify") + rest})), [])

    def test_indexed_context_and_whitespace_prevent_rekey(self):
        for run in ("echo ${{ github['job'] }}", 'echo ${{ github [ "job" ] }}',
                    "echo ${{ github['workflow_ref'] }}", "echo ${{ github . job }}",
                    "echo ${{ (github).job }}", "echo ${{ (( github )).workflow_ref }}",
                    "echo ${{ github.repository }}"):
            self.assertTrue(drops(scan({P: wf(run=run)}, {P: wf("verify", run)})))

    def test_unadmitted_job_stays_deleted_beside_admitted_move(self):
        rs = json.dumps({"rules": [{"type": "required_status_checks", "parameters": {"required_status_checks": [{"context": "tripwire"}, {"context": "dependent"}]}}]}).encode()
        body = wf() + b"  next:\n    name: dependent\n    needs: gate\n    runs-on: ubuntu-latest\n    steps:\n      - run: check\n"
        r = scan_pair({R: rs, P: body}, {R: rs, N: body}, base_label="b", head_label="h", env={"PINWASH_TODAY": "2026-10-14"})
        self.assertEqual([f["before"] for f in drops(r)], ["dependent"])
