#
# Copyright (C) 2020 Red Hat, Inc.
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

from pyanaconda.core.configuration.anaconda import conf
from pyanaconda.core.dbus import DBus
from pyanaconda.core.signal import Signal
from pyanaconda.modules.common.base import KickstartService
from pyanaconda.modules.common.containers import TaskContainer
from pyanaconda.modules.common.structures.requirement import Requirement

from org_fedora_oscap import common
from org_fedora_oscap.constants import OSCAP
from org_fedora_oscap.service.installation import FetchContentTask, CheckFingerprintTask, \
    EvaluateRulesTask, InstallContentTask, RemediateSystemTask
from org_fedora_oscap.service.kickstart import OSCAPKickstartSpecification
from org_fedora_oscap.service.oscap_interface import OSCAPInterface
from org_fedora_oscap.structures import PolicyData

log = logging.getLogger(__name__)

__all__ = ["OSCAPService"]


class OSCAPService(KickstartService):
    """The implementation of the OSCAP service."""

    def __init__(self):
        """Create a service."""
        super().__init__()
        self._policy_enabled = True
        self.policy_enabled_changed = Signal()

        self._policy_data = PolicyData()
        self.policy_data_changed = Signal()

    @property
    def policy_enabled(self):
        """Is the security policy enabled?

        :return: True or False
        """
        return self._policy_enabled

    @policy_enabled.setter
    def policy_enabled(self, value):
        """Should be the security policy enabled?

        :param value: True or False
        """
        self._policy_enabled = value
        self.policy_enabled_changed.emit()
        log.debug("Policy enabled is set to '%s'.", value)

    @property
    def policy_data(self):
        """The security policy data.

        :return: an instance of PolicyData
        """
        return self._policy_data

    @policy_data.setter
    def policy_data(self, value):
        """Set the security policy data.

        :param value: an instance of PolicyData
        """
        self._policy_data = value
        self.policy_data_changed.emit()
        log.debug("Policy data is set to '%s'.", value)

    def publish(self):
        """Publish the DBus objects."""
        TaskContainer.set_namespace(OSCAP.namespace)
        DBus.publish_object(OSCAP.object_path, OSCAPInterface(self))
        DBus.register_service(OSCAP.service_name)

    @property
    def kickstart_specification(self):
        """Return the kickstart specification."""
        return OSCAPKickstartSpecification

    def process_kickstart(self, data):
        """Process the kickstart data."""
        addon_data = data.addons.org_fedora_oscap
        policy_data = PolicyData()

        policy_data.content_type = addon_data.content_type
        policy_data.content_url = addon_data.content_url
        policy_data.datastream_id = addon_data.datastream_id
        policy_data.xccdf_id = addon_data.xccdf_id
        policy_data.profile_id = addon_data.profile_id
        policy_data.content_path = addon_data.content_path
        policy_data.cpe_path = addon_data.cpe_path
        policy_data.tailoring_path = addon_data.tailoring_path
        policy_data.fingerprint = addon_data.fingerprint
        policy_data.certificates = addon_data.certificates

        self.policy_data = policy_data

    def setup_kickstart(self, data):
        """Set the given kickstart data."""
        policy_data = self.policy_data
        addon_data = data.addons.org_fedora_oscap

        addon_data.content_type = policy_data.content_type
        addon_data.content_url = policy_data.content_url
        addon_data.datastream_id = policy_data.datastream_id
        addon_data.xccdf_id = policy_data.xccdf_id
        addon_data.profile_id = policy_data.profile_id
        addon_data.content_path = policy_data.content_path
        addon_data.cpe_path = policy_data.cpe_path
        addon_data.tailoring_path = policy_data.tailoring_path
        addon_data.fingerprint = policy_data.fingerprint
        addon_data.certificates = policy_data.certificates

    def collect_requirements(self):
        """Return installation requirements.

        :return: a list of requirements
        """
        requirements = []

        if self.policy_enabled and self.policy_data.profile_id:
            requirements.extend([
                Requirement.for_package(
                    package_name="openscap",
                    reason="Required by oscap add-on."
                ),
                Requirement.for_package(
                    package_name="openscap-scanner",
                    reason="Required by oscap add-on."
                )
            ])

            if self.policy_data.content_type == "scap-security-guide":
                requirements.append(
                    Requirement.for_package(
                        package_name="scap-security-guide",
                        reason="Required by oscap add-on."
                    )
                )

        return requirements

    def configure_with_tasks(self):
        """Return configuration tasks.

        :return: a list of tasks
        """
        return [
            FetchContentTask(
                policy_enabled=self.policy_enabled,
                policy_data=self.policy_data,
                file_path=common.get_raw_preinst_content_path(self.policy_data),
                content_path=common.get_preinst_content_path(self.policy_data),
            ),
            CheckFingerprintTask(
                policy_enabled=self.policy_enabled,
                policy_data=self.policy_data,
                file_path=common.get_raw_preinst_content_path(self.policy_data),
            ),
            EvaluateRulesTask(
                policy_enabled=self.policy_enabled,
                policy_data=self.policy_data,
                content_path=common.get_preinst_content_path(self.policy_data),
                tailoring_path=common.get_preinst_tailoring_path(self.policy_data),
            ),
        ]

    def install_with_tasks(self):
        """Return installation tasks.

        :return: a list of tasks
        """
        return [
            InstallContentTask(
                sysroot=conf.target.system_root,
                policy_enabled=self.policy_enabled,
                policy_data=self.policy_data,
                file_path=common.get_raw_preinst_content_path(self.policy_data),
                content_path=common.get_preinst_content_path(self.policy_data),
                tailoring_path=common.get_preinst_tailoring_path(self.policy_data),
                target_directory=common.TARGET_CONTENT_DIR,
            ),
            RemediateSystemTask(
                sysroot=conf.target.system_root,
                policy_enabled=self.policy_enabled,
                policy_data=self.policy_data,
                target_content_path=common.get_postinst_content_path(self.policy_data),
                target_tailoring_path=common.get_preinst_tailoring_path(self.policy_data)
            )
        ]
