# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Unit tests for DNS and SSL certificate diagnostic script."""

import json
import socket
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from scripts.check_dns_status import (
    check_dns_resolution,
    check_gcp_ssl_certificate,
    check_gke_managed_certificate,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


def test_check_dns_resolution_success_without_expected_ip():
    """Verify check_dns_resolution passes when domain resolves."""
    fake_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("34.120.50.1", 443))]
    with patch("socket.getaddrinfo", return_value=fake_addrinfo):
        ok, ips, msg = check_dns_resolution("gateway.example.com")
        assert ok is True
        assert ips == ["34.120.50.1"]
        assert "resolves to: 34.120.50.1" in msg


def test_check_dns_resolution_matching_expected_ip():
    """Verify check_dns_resolution matches the expected IP address."""
    fake_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("34.120.50.1", 443))]
    with patch("socket.getaddrinfo", return_value=fake_addrinfo):
        ok, ips, msg = check_dns_resolution("gateway.example.com", expected_ip="34.120.50.1")
        assert ok is True
        assert ips == ["34.120.50.1"]
        assert "correctly resolves to expected IP" in msg


def test_check_dns_resolution_mismatch_expected_ip():
    """Verify check_dns_resolution detects IP mismatch."""
    fake_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("34.120.50.1", 443))]
    with patch("socket.getaddrinfo", return_value=fake_addrinfo):
        ok, ips, msg = check_dns_resolution("gateway.example.com", expected_ip="35.200.10.2")
        assert ok is False
        assert ips == ["34.120.50.1"]
        assert "do not match expected IP" in msg


def test_check_dns_resolution_failure():
    """Verify check_dns_resolution handles socket.gaierror gracefully."""
    with patch("socket.getaddrinfo", side_effect=socket.gaierror("Name or service not known")):
        ok, ips, msg = check_dns_resolution("nonexistent.invalid")
        assert ok is False
        assert ips == []
        assert "DNS lookup failed" in msg


def test_check_gcp_ssl_certificate_active():
    """Verify check_gcp_ssl_certificate parses ACTIVE status."""
    fake_output = json.dumps({
        "managed": {
            "status": "ACTIVE",
            "domainStatus": {"gateway.example.com": "ACTIVE"}
        }
    })
    mock_run = MagicMock(returncode=0, stdout=fake_output, stderr="")
    with patch("shutil.which", return_value="/usr/bin/gcloud"):
        with patch("subprocess.run", return_value=mock_run):
            is_active, msg, data = check_gcp_ssl_certificate("gateway-cert", project_id="test-proj")
            assert is_active is True
            assert "ACTIVE" in msg
            assert data["managed"]["status"] == "ACTIVE"


def test_check_gcp_ssl_certificate_provisioning():
    """Verify check_gcp_ssl_certificate detects PROVISIONING status."""
    fake_output = json.dumps({
        "managed": {
            "status": "PROVISIONING",
            "domainStatus": {"gateway.example.com": "PROVISIONING"}
        }
    })
    mock_run = MagicMock(returncode=0, stdout=fake_output, stderr="")
    with patch("shutil.which", return_value="/usr/bin/gcloud"):
        with patch("subprocess.run", return_value=mock_run):
            is_active, msg, _ = check_gcp_ssl_certificate("gateway-cert")
            assert is_active is False
            assert "PROVISIONING" in msg


def test_check_gke_managed_certificate_active():
    """Verify check_gke_managed_certificate parses Active status from Kubernetes."""
    fake_output = json.dumps({
        "status": {
            "certificateStatus": "Active",
            "domainStatus": [{"domain": "gateway.example.com", "status": "Active"}]
        }
    })
    mock_run = MagicMock(returncode=0, stdout=fake_output, stderr="")
    with patch("shutil.which", return_value="/usr/bin/kubectl"):
        with patch("subprocess.run", return_value=mock_run):
            is_active, msg, data = check_gke_managed_certificate("gateway-managed-cert")
            assert is_active is True
            assert "Active" in msg
            assert data["status"]["certificateStatus"] == "Active"

