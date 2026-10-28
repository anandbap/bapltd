import unittest
import sys
import os

sys.path.insert(0, os.path.abspath("."))

test_files = [
    "tests.test_agent_lifecycle_matrix",
    "tests.test_agent_watch_v2",
    "tests.test_bap_530_egress_control",
    "tests.test_bap_534_535_538",
    "tests.test_bap_536_adversarial_scanner",
    "tests.test_bap_537_tamper_and_quarantine",
    "tests.test_bap_539_multi_harness",
    "tests.test_bap_epic32_agent_auth",
    "tests.test_bap_install_multiplatform",
    "tests.test_bap200_sole_executor",
    "tests.test_bap714_containment_redteam",
    "tests.test_bounded_authority_matrix",
    "tests.test_cedar_policy_studio",
    "tests.test_control_plane",
    "tests.test_crash_recovery_sweep",
    "tests.test_demo_remote_cio",
    "tests.test_device_identity_and_remote_sync",
    "tests.test_e2e_adversarial_hardening",
    "tests.test_e2e_fortified_identities_and_launchers",
    "tests.test_endpoint_layered_enforcement",
    "tests.test_enterprise_idp_oidc",
    "tests.test_executive_demo",
    "tests.test_gateway_pep",
    "tests.test_governance_extension",
    "tests.test_harness_multi_session",
    "tests.test_hitl_and_supply_chain",
    "tests.test_http_client_auto_grant",
    "tests.test_intent_telemetry",
    "tests.test_kms_audit_notarization",
    "tests.test_leak",
    "tests.test_mcp_server",
    "tests.test_multi_layer_defense",
    "tests.test_packaging_and_cicd",
    "tests.test_persona_activity",
    "tests.test_private_credentials_and_certs",
    "tests.test_prompt_injection_defense",
    "tests.test_python_agent_negative",
    "tests.test_python_agent",
    "tests.test_scoped_pinning_and_sweep",
    "tests.test_shadow_it_discovery",
    "tests.test_spiffe_tpm_kernel_sandboxing",
    "tests.test_stop_revoke_lifecycle",
    "tests.test_v3_ui_live",
    "tests.test_vendor_interop",
    "tests.test_version_compatibility",
]

loader = unittest.TestLoader()
failed_suites = []

for mod in test_files:
    try:
        suite = loader.loadTestsFromName(mod)
        runner = unittest.TextTestRunner(stream=sys.stdout, verbosity=0)
        res = runner.run(suite)
        if not res.wasSuccessful():
            failed_suites.append((mod, len(res.failures), len(res.errors)))
            print(f"FAILED: {mod} (failures={len(res.failures)}, errors={len(res.errors)})")
        else:
            print(f"PASSED: {mod}")
    except Exception as e:
        failed_suites.append((mod, str(e)))
        print(f"ERROR: {mod}: {e}")

print("=" * 60)
if failed_suites:
    print(f"Failed suites: {failed_suites}")
    sys.exit(1)
else:
    print("ALL SUITES PASSED!")
