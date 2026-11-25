from __future__ import annotations

import json
import unittest
from pathlib import Path


TEMPLATE_PATH = (
    Path(__file__).resolve().parents[1]
    / "infrastructure"
    / "aws-waf-alb.template.json"
)


class AwsWafTemplateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.template = json.loads(TEMPLATE_PATH.read_text(encoding="utf-8"))
        cls.resources = cls.template["Resources"]

    def test_template_attaches_regional_acl_to_existing_alb_without_creating_public_origin(self) -> None:
        acl = self.resources["ProductionWebACL"]
        association = self.resources["ProtectApplicationLoadBalancer"]

        self.assertEqual(acl["Type"], "AWS::WAFv2::WebACL")
        self.assertEqual(acl["Properties"]["Scope"], "REGIONAL")
        self.assertEqual(
            association["Type"],
            "AWS::WAFv2::WebACLAssociation",
        )
        self.assertEqual(
            association["Properties"]["ResourceArn"],
            {"Ref": "ApplicationLoadBalancerArn"},
        )
        self.assertEqual(
            association["Properties"]["WebACLArn"],
            {"Fn::GetAtt": ["ProductionWebACL", "Arn"]},
        )
        self.assertEqual(
            {resource["Type"] for resource in self.resources.values()},
            {
                "AWS::Logs::LogGroup",
                "AWS::WAFv2::WebACL",
                "AWS::WAFv2::LoggingConfiguration",
                "AWS::WAFv2::WebACLAssociation",
            },
        )
        self.assertEqual(
            self.template["Parameters"]["ManagedRuleActionMode"]["Default"],
            "BLOCK",
        )

    def test_acl_uses_aws_managed_protections_and_per_ip_rate_limit(self) -> None:
        rules = self.resources["ProductionWebACL"]["Properties"]["Rules"]
        priorities = [rule["Priority"] for rule in rules]
        self.assertEqual(priorities, sorted(set(priorities)))

        for rule in rules:
            if "ManagedRuleGroupStatement" not in rule["Statement"]:
                continue
            self.assertEqual(
                rule["OverrideAction"]["Fn::If"],
                ["CountManagedRules", {"Count": {}}, {"None": {}}],
            )

        managed_groups = {
            rule["Statement"]["ManagedRuleGroupStatement"]["Name"]
            for rule in rules
            if "ManagedRuleGroupStatement" in rule["Statement"]
        }
        self.assertEqual(
            managed_groups,
            {
                "AWSManagedRulesAmazonIpReputationList",
                "AWSManagedRulesCommonRuleSet",
                "AWSManagedRulesKnownBadInputsRuleSet",
                "AWSManagedRulesSQLiRuleSet",
            },
        )
        rate_rule = next(rule for rule in rules if rule["Name"] == "PerIpRateLimit")
        rate_statement = rate_rule["Statement"]["RateBasedStatement"]
        self.assertEqual(rate_statement["AggregateKeyType"], "IP")
        self.assertEqual(rate_statement["EvaluationWindowSec"], 300)
        self.assertEqual(rate_statement["Limit"], {"Ref": "RateLimit"})
        self.assertEqual(
            rate_rule["Action"]["Fn::If"],
            ["CountManagedRules", {"Count": {}}, {"Block": {}}],
        )

    def test_waf_logging_redacts_sensitive_fields_and_retains_logs(self) -> None:
        logging = self.resources["ProductionWebACLLogging"]
        redactions = logging["Properties"]["RedactedFields"]
        self.assertIn({"SingleHeader": {"Name": "authorization"}}, redactions)
        self.assertIn({"SingleHeader": {"Name": "cookie"}}, redactions)
        self.assertIn({"QueryString": {}}, redactions)

        log_group = self.resources["WafLogGroup"]
        self.assertEqual(log_group["DeletionPolicy"], "Retain")
        self.assertEqual(log_group["UpdateReplacePolicy"], "Retain")
        self.assertEqual(
            log_group["Properties"]["LogGroupName"],
            {"Fn::Sub": "aws-waf-logs-${AWS::StackName}"},
        )
        self.assertIn("KmsKeyId", log_group["Properties"])


if __name__ == "__main__":
    unittest.main()
