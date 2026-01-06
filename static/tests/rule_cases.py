from __future__ import annotations

from static.rules.checkout_hardening import CheckoutCredentialPersistenceRule
from static.rules.dangerous_triggers import DangerousTriggersRule
from static.rules.debug_tracing import DebugTracingRule
from static.rules.docker_image_pinning import DockerImagePinningRule
from static.rules.gitlab_artifact_exposure import GitLabArtifactExposureRule
from static.rules.gitlab_insecure_includes import GitLabInsecureIncludesRule
from static.rules.gitlab_privileged_runner import GitLabPrivilegedRunnerRule
from static.rules.gitlab_secrets_exposure import GitLabSecretsExposureRule
from static.rules.hardcoded_secrets import HardcodedSecretsRule
from static.rules.insecure_downloads import InsecureDownloadsRule
from static.rules.oidc_permissions import OIDCPermissionsRule
from static.rules.permissions import ExcessivePermissionsRule
from static.rules.pr_target_checkout import PRTargetUntrustedCheckoutRule
from static.rules.secret_exposure import SecretExposureRule
from static.rules.self_hosted_runners import SelfHostedRunnerRule
from static.rules.suspicious_env import SuspiciousEnvRule
from static.rules.third_party_action_secrets import ThirdPartyActionSecretsRule
from static.rules.unpinned_actions import UnpinnedActionsRule
from static.rules.untrusted_pr_target import UntrustedCodeOnPRTargetRule


def trigger_cases() -> dict[type, dict]:
    return {
        CheckoutCredentialPersistenceRule: {
            "jobs": {"build": {"steps": [{"uses": "actions/checkout@v4"}]}}
        },
        DangerousTriggersRule: {"on": {"pull_request_target": {}}},
        DebugTracingRule: {"env": {"ACTIONS_STEP_DEBUG": "true"}},
        DockerImagePinningRule: {
            "jobs": {"build": {"steps": [{"uses": "docker://alpine:latest"}]}}
        },
        GitLabArtifactExposureRule: {
            "build": {"artifacts": {"paths": [".env"]}},
        },
        GitLabInsecureIncludesRule: {
            "include": [{"remote": "https://gitlab.example.com/group/-/raw/main/ci.yml"}],
        },
        GitLabPrivilegedRunnerRule: {
            "build": {"privileged": True},
        },
        GitLabSecretsExposureRule: {
            "variables": {"DEPLOY_PASSWORD": "SuperSecretPassword123456"},
        },
        HardcodedSecretsRule: {
            "env": {"AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE"},
        },
        InsecureDownloadsRule: {
            "jobs": {
                "build": {"steps": [{"run": "curl -fsSL https://example.com/a.sh | bash"}]}
            }
        },
        OIDCPermissionsRule: {"permissions": {"id-token": "write"}},
        ExcessivePermissionsRule: {},
        PRTargetUntrustedCheckoutRule: {
            "on": {"pull_request_target": {}},
            "jobs": {
                "build": {
                    "steps": [
                        {
                            "uses": "actions/checkout@v4",
                            "with": {"ref": "${{ github.event.pull_request.head.sha }}"},
                        }
                    ]
                }
            },
        },
        SecretExposureRule: {
            "jobs": {
                "build": {
                    "steps": [
                        {"run": 'echo "token=${{ secrets.DEPLOY_TOKEN }}"'},
                    ]
                }
            }
        },
        SelfHostedRunnerRule: {"jobs": {"build": {"runs-on": ["self-hosted", "linux"]}}},
        SuspiciousEnvRule: {"env": {"DB_PASSWORD": "PlainPassword123456"}},
        ThirdPartyActionSecretsRule: {
            "jobs": {
                "build": {
                    "steps": [
                        {
                            "uses": "somecorp/action@v1",
                            "env": {"TOKEN": "${{ secrets.API_KEY }}"},
                        }
                    ]
                }
            }
        },
        UnpinnedActionsRule: {
            "jobs": {"build": {"steps": [{"uses": "actions/checkout@v4"}]}}
        },
        UntrustedCodeOnPRTargetRule: {
            "on": {"pull_request_target": {}},
            "jobs": {"build": {"steps": [{"run": "./scripts/user-provided.sh"}]}},
        },
    }


def safe_cases() -> dict[type, dict]:
    return {
        CheckoutCredentialPersistenceRule: {
            "jobs": {
                "build": {
                    "steps": [
                        {
                            "uses": "actions/checkout@v4",
                            "with": {"persist-credentials": False},
                        }
                    ]
                }
            }
        },
        DangerousTriggersRule: {"on": {"pull_request": {}}},
        DebugTracingRule: {"jobs": {"build": {"steps": [{"run": "echo hello"}]}}},
        DockerImagePinningRule: {
            "jobs": {
                "build": {
                    "steps": [
                        {
                            "uses": "docker://alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        }
                    ]
                }
            }
        },
        GitLabArtifactExposureRule: {
            "build": {"artifacts": {"paths": ["dist/report.txt"]}},
        },
        GitLabInsecureIncludesRule: {
            "include": [
                {
                    "remote": "https://gitlab.example.com/group/-/raw/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/ci.yml"
                },
                {"project": "group/templates", "file": "/base.yml", "ref": "v1.0.0"},
            ],
        },
        GitLabPrivilegedRunnerRule: {
            "build": {
                "image": "alpine:3.20",
                "services": [{"name": "redis:7"}],
                "script": ["echo ok"],
            },
        },
        GitLabSecretsExposureRule: {
            "variables": {"CI_JOB_TOKEN": "$CI_JOB_TOKEN"},
            "build": {"script": ["echo ok"]},
        },
        HardcodedSecretsRule: {"env": {"FOO": "bar"}},
        InsecureDownloadsRule: {
            "jobs": {
                "build": {
                    "steps": [
                        {"run": "curl -fsSL https://example.com/a.sh -o a.sh && bash a.sh"}
                    ]
                }
            }
        },
        OIDCPermissionsRule: {"permissions": {"contents": "read", "id-token": "read"}},
        ExcessivePermissionsRule: {"permissions": {"contents": "read"}},
        PRTargetUntrustedCheckoutRule: {
            "on": {"pull_request_target": {}},
            "jobs": {
                "build": {
                    "steps": [
                        {
                            "uses": "actions/checkout@v4",
                            "with": {"ref": "main"},
                        }
                    ]
                }
            },
        },
        SecretExposureRule: {
            "jobs": {
                "build": {
                    "steps": [
                        {"run": "echo safe"},
                        {
                            "uses": "actions/upload-artifact@v4",
                            "with": {"path": "dist/report.txt"},
                        },
                    ]
                }
            }
        },
        SelfHostedRunnerRule: {"jobs": {"build": {"runs-on": "ubuntu-latest"}}},
        SuspiciousEnvRule: {"env": {"DB_PASSWORD": "${{ secrets.DB_PASSWORD }}"}},
        ThirdPartyActionSecretsRule: {
            "jobs": {
                "build": {
                    "steps": [{"uses": "somecorp/action@v1", "with": {"mode": "safe"}}]
                }
            }
        },
        UnpinnedActionsRule: {
            "jobs": {
                "build": {
                    "steps": [
                        {
                            "uses": "actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        }
                    ]
                }
            }
        },
        UntrustedCodeOnPRTargetRule: {
            "on": {"pull_request_target": {}},
            "jobs": {"build": {"steps": [{"run": "echo hello"}]}},
        },
    }
