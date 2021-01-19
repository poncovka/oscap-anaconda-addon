#
# Copyright (C) 2021  Red Hat, Inc.
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions of
# the GNU General Public License v.2, or (at your option) any later version.
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY expressed or implied, including the implied warranties of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General
# Public License for more details.  You should have received a copy of the
# GNU General Public License along with this program; if not, write to the
# Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.  Any Red Hat trademarks that are incorporated in the
# source code or documentation are not subject to the GNU General Public
# License and may only be used or replicated with the express permission of
# Red Hat, Inc.
#
import logging

from org_fedora_oscap.service import installation
from org_fedora_oscap.structures import PolicyData

# FIXME: Extend the tests to test all paths of the installation tasks.


def test_fetch_content_task(caplog):
    data = PolicyData()
    task = installation.FetchContentTask(
        policy_enabled=False,
        policy_data=data,
        file_path="/file/path",
        content_path="/content/path",
    )

    with caplog.at_level(logging.DEBUG):
        task.run()

    assert task.name == "Fetch the content"
    assert "The security policy is disabled. Skip." in caplog.text


def test_check_fingerprint_task(caplog):
    data = PolicyData()
    task = installation.CheckFingerprintTask(
        policy_enabled=False,
        policy_data=data,
        file_path="/file/path"
    )

    with caplog.at_level(logging.DEBUG):
        task.run()

    assert task.name == "Check the fingerprint"
    assert "The security policy is disabled. Skip." in caplog.text


def test_evaluate_rules_task(caplog):
    data = PolicyData()
    task = installation.EvaluateRulesTask(
        policy_enabled=False,
        policy_data=data,
        content_path="/content/path",
        tailoring_path="/tailoring/path"
    )

    with caplog.at_level(logging.DEBUG):
        task.run()

    assert task.name == "Evaluate the rules"
    assert "The security policy is disabled. Skip." in caplog.text


def test_install_content_task(caplog):
    data = PolicyData()
    task = installation.InstallContentTask(
        sysroot="/sysroot/path",
        policy_enabled=False,
        policy_data=data,
        file_path="/file/path",
        content_path="/content/path",
        tailoring_path="/tailoring/path",
        target_directory="target_dir"
    )

    with caplog.at_level(logging.DEBUG):
        task.run()

    assert task.name == "Install the content"
    assert "The security policy is disabled. Skip." in caplog.text


def test_remediate_system_task(caplog):
    data = PolicyData()
    task = installation.RemediateSystemTask(
        sysroot="/sysroot/path",
        policy_enabled=False,
        policy_data=data,
        target_content_path="/target/content/path",
        target_tailoring_path="/target/tailoring/path"
    )

    with caplog.at_level(logging.DEBUG):
        task.run()

    assert task.name == "Remediate the system"
    assert "The security policy is disabled. Skip." in caplog.text
