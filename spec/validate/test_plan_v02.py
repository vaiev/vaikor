# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
"""Runs the VKR-L3 v0.2 vectors (spec/test-vectors/plan-v0.2) through the reference checker.

    python -m pytest spec/validate/test_plan_v02.py
"""
import json
import pathlib
import unittest

import plan_v02
import validate

VECTORS = pathlib.Path(__file__).resolve().parent.parent / "test-vectors" / "plan-v0.2"
SUITES = ("expr", "verify", "flow", "run")


def load(suite):
    return json.loads((VECTORS / f"{suite}.json").read_text(encoding="utf-8"))["vectors"]


def actual(vector):
    op, data = vector["operation"], vector["input"]
    extra = {k: data[k] for k in ("prompts", "views") if k in data}
    if op == "expr-eval":
        return plan_v02.expr_eval(data["env"], data["expr"])
    if op == "plan-verify":
        return plan_v02.plan_verify(data["plan"], data["catalog"], data["policy"], **extra)
    if op == "plan-flows":
        return plan_v02.plan_flows(data["plan"], data["catalog"], **extra)
    if op == "plan-run":
        return plan_v02.plan_run(data["plan"], data["catalog"], data.get("inputs"), data["script"], **extra)
    raise AssertionError(op)


class PlanV02Vectors(unittest.TestCase):
    def test_every_vector_matches(self):
        for suite in SUITES:
            for vector in load(suite):
                with self.subTest(vector["id"]):
                    self.assertEqual(actual(vector), vector["expected"]["value"], vector.get("note"))

    def test_plans_match_the_schema(self):
        schemas, registry = validate.load_checked()
        for suite in SUITES[1:]:
            for vector in load(suite):
                with self.subTest(vector["id"]):
                    problems = validate.validate_document(vector["input"]["plan"], "plan-v02", schemas, registry)
                    self.assertEqual(problems, [])

    def test_run_vectors_use_accepted_plans(self):
        for vector in load("run"):
            data = vector["input"]
            extra = {k: data[k] for k in ("prompts", "views") if k in data}
            with self.subTest(vector["id"]):
                self.assertEqual(plan_v02.plan_verify(data["plan"], data["catalog"], "permit-all", **extra),
                                 {"verdict": "accept"})

    def test_ids_are_consecutive(self):
        for suite in SUITES:
            ids = [v["id"] for v in load(suite)]
            self.assertEqual(ids, [f"plan.v02-{suite}.{i:03d}" for i in range(1, len(ids) + 1)])

    def test_the_schema_and_the_checker_agree_on_structure(self):
        """A structurally broken plan is refused by both, a sound one by neither."""
        schemas, registry = validate.load_checked()
        sound = load("verify")[1]["input"]
        broken = [
            {**sound["plan"], "v": "0.1"},
            {**sound["plan"], "extra": 1},
            {**sound["plan"], "steps": []},
            {**sound["plan"], "steps": [{**sound["plan"]["steps"][0], "expr": "1"}]},
            {**sound["plan"], "steps": [{**sound["plan"]["steps"][0], "args": {"x": {"lit": None}}}]},
            {**sound["plan"], "steps": [{**sound["plan"]["steps"][0], "args": {"x": {"lit": 1.5}}}]},
        ]
        for plan in broken:
            with self.subTest(json.dumps(plan)[:60]):
                self.assertTrue(validate.validate_document(plan, "plan-v02", schemas, registry))
                verdict = plan_v02.plan_verify(plan, sound["catalog"], "permit-all")
                self.assertEqual(verdict["verdict"], "reject")
                self.assertTrue(verdict["problems"][0]["code"].startswith("W-"))


if __name__ == "__main__":
    unittest.main()
