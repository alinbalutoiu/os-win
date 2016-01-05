# Copyright 2015 Cloudbase Solutions Srl
#
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import collections
import ctypes
import mock
from oslotest import base

from os_win import _utils
from os_win import exceptions
from os_win.utils.storage.initiator import iscsi_utils
from os_win.utils.storage.initiator import iscsidsc_structures as iscsi_struct
from os_win.utils.storage.initiator import iscsierr


class ISCSIInitiatorUtilsTestCase(base.BaseTestCase):
    """Unit tests for the Hyper-V ISCSIInitiatorUtils class."""

    def setUp(self):
        super(ISCSIInitiatorUtilsTestCase, self).setUp()
        self._setup_lib_mocks()

        def mock_init(self):
            self._win32utils = mock.MagicMock()

        with mock.patch.object(iscsi_utils.ISCSIInitiatorUtils, '__init__',
                               new=mock_init):
            self._initiator = iscsi_utils.ISCSIInitiatorUtils()

        self._run_mocker = mock.patch.object(self._initiator,
                                             '_run_and_check_output')
        self._run_mocker.start()
        self._mock_run = self._initiator._run_and_check_output

        iscsi_utils.portal_map = collections.defaultdict(set)

    def _setup_lib_mocks(self):
        iscsi_utils.iscsidsc = mock.Mock()
        self._iscsidsc = iscsi_utils.iscsidsc
        self._ctypes = mock.Mock()
        # This is used in order to easily make assertions on the variables
        # passed by reference.
        self._ctypes.byref = lambda x: (x, "byref")

        self.patch_ctypes = mock.patch.object(iscsi_utils, 'ctypes',
                                              new=self._ctypes)
        self.patch_ctypes.start()

    def _test_update_portal_map(self, remove=False):
        fake_portal = "%s:%s" % (mock.sentinel.target_addr,
                                 mock.sentinel.target_port)

        if remove:
            iscsi_utils.portal_map[fake_portal].add(mock.sentinel.target_iqn)

        update_portal_map = _utils.get_wrapped_function(
            self._initiator._update_portal_map)
        update_portal_map(
            self,
            mock.sentinel.target_addr,
            mock.sentinel.target_port,
            target_iqn=mock.sentinel.target_iqn,
            remove=remove)

        if not remove:
            self.assertIn(fake_portal, iscsi_utils.portal_map)
            actual_target_iqn = iscsi_utils.portal_map.get(fake_portal)
            self.assertEqual(set([mock.sentinel.target_iqn]),
                             actual_target_iqn)
        else:
            self.assertNotIn(fake_portal, iscsi_utils.portal_map)

    def test_update_portal_map(self):
        self._test_update_portal_map()

    def test_remove_portal_from_map(self):
        self._test_update_portal_map(remove=True)

    def test_portal_in_use(self):
        fake_portal = "%s:%s" % (mock.sentinel.target_addr,
                                 mock.sentinel.target_port)
        iscsi_utils.portal_map[fake_portal].add(mock.sentinel.target_iqn)

        portal_in_use = self._initiator._portal_in_use(
            mock.sentinel.target_addr, mock.sentinel.target_port)

        self.assertTrue(portal_in_use)

    def test_portal_not_used(self):
        self.assertFalse(self._initiator._portal_in_use(
            mock.sentinel.target_addr, mock.sentinel.target_port))

    @mock.patch.object(iscsi_utils.ISCSIInitiatorUtils, '_update_portal_map')
    @mock.patch.object(iscsi_utils.ISCSIInitiatorUtils,
                       '_get_iscsi_persistent_logins')
    @mock.patch.object(iscsi_utils.ISCSIInitiatorUtils, '_get_iscsi_sessions')
    def test_refresh_used_portals(self, mock_get_iscsi_sessions,
                                  mock_get_iscsi_persistent_logins,
                                  mock_update_portal_map):
        fake_connection = mock.MagicMock()
        fake_session = mock.MagicMock()
        fake_persistent_logins = mock.MagicMock()

        fake_connection.TargetAddress = mock.sentinel.TargetAddress
        fake_connection.TargetSocket = mock.sentinel.TargetSocket
        fake_session.Connections = [fake_connection]
        fake_session.ConnectionCount = len(fake_session.Connections)
        fake_session.TargetNodeName = mock.sentinel.target_iqn

        mock_get_iscsi_sessions.return_value = [fake_session]
        mock_get_iscsi_persistent_logins.return_value = [
            fake_persistent_logins]

        self._initiator._refresh_used_portals()

        mock_get_iscsi_sessions.assert_called_once_with()
        mock_update_portal_map.assert_has_calls([
            mock.call(mock.sentinel.TargetAddress,
                      mock.sentinel.TargetSocket,
                      mock.sentinel.target_iqn),
            mock.call(fake_persistent_logins.TargetPortal.Address,
                      fake_persistent_logins.TargetPortal.Socket,
                      fake_persistent_logins.TargetName)])
        mock_get_iscsi_persistent_logins.assert_called_once_with()

    def test_run_and_check_output(self):
        self._run_mocker.stop()
        self._initiator._win32utils = mock.MagicMock()
        mock_win32utils_run_and_check_output = (
            self._initiator._win32utils.run_and_check_output)

        self._initiator._run_and_check_output()

        mock_win32utils_run_and_check_output.assert_called_once_with(
            error_msg_src=iscsierr.err_msg_dict)

    def _test_add_target_portal(self, login_opts=True):
        self._initiator._add_target_portal(mock.sentinel.portal,
                                           login_opts=login_opts)

        login_opts_ref = self._ctypes.byref(login_opts) if login_opts else None

        ignored_error_codes = [iscsierr.ISDSC_INITIATOR_NODE_ALREADY_EXISTS]
        self._mock_run.assert_called_once_with(
            self._iscsidsc.AddIScsiSendTargetPortalW,
            None,
            self._ctypes.c_ulong.return_value,
            login_opts_ref,
            self._ctypes.c_ulonglong.return_value,
            self._ctypes.byref(mock.sentinel.portal),
            ignored_error_codes=ignored_error_codes)
        self._ctypes.c_ulong.assert_called_once_with(
            iscsi_struct.ISCSI_ALL_INITIATOR_PORTS)
        self._ctypes.c_ulonglong.assert_called_once_with(
            iscsi_struct.ISCSI_DEFAULT_SECURITY_FLAGS)

    def test_add_portal_without_login_opts(self):
        self._test_add_target_portal(login_opts=False)

    def test_add_target_portal(self):
        self._test_add_target_portal()

    def test_remove_target_portal(self):
        self._initiator._remove_target_portal(mock.sentinel.portal)

        ignored_error_codes = [iscsierr.ISDSC_PORTAL_NOT_FOUND]
        self._mock_run.assert_called_once_with(
            self._iscsidsc.RemoveIScsiSendTargetPortalW,
            None,
            self._ctypes.c_ulong.return_value,
            self._ctypes.byref(mock.sentinel.portal),
            ignored_error_codes=ignored_error_codes)
        self._ctypes.c_ulong.assert_called_once_with(
            iscsi_struct.ISCSI_ALL_INITIATOR_PORTS)

    def test_refresh_target_portal(self):
        self._initiator._refresh_target_portal(mock.sentinel.portal)

        self._mock_run.assert_called_once_with(
            self._iscsidsc.RefreshIScsiSendTargetPortalW,
            None,
            self._ctypes.c_ulong.return_value,
            self._ctypes.byref(mock.sentinel.portal))
        self._ctypes.c_ulong.assert_called_once_with(
            iscsi_struct.ISCSI_ALL_INITIATOR_PORTS)

    def test_get_portals_exporting_target(self):
        _get_portals_exporting_target = _utils.get_wrapped_function(
            self._initiator._get_portals_exporting_target)
        _get_portals_exporting_target(
            self._initiator,
            mock.sentinel.target_name,
            buff=mock.sentinel.buff,
            element_count=mock.sentinel.element_count)

        self._mock_run.assert_called_once_with(
            self._iscsidsc.ReportIScsiTargetPortalsW,
            None,
            self._ctypes.c_wchar_p.return_value,
            None,
            self._ctypes.byref(mock.sentinel.element_count),
            self._ctypes.byref(mock.sentinel.buff))

    def test_get_iscsi_persistent_logins(self):
        _get_iscsi_persistent_logins = _utils.get_wrapped_function(
            self._initiator._get_iscsi_persistent_logins)
        _get_iscsi_persistent_logins(
            self._initiator,
            buff=mock.sentinel.buff,
            buff_size=mock.sentinel.buff_size,
            element_count=mock.sentinel.element_count)

        self._mock_run.assert_called_once_with(
            self._iscsidsc.ReportIScsiPersistentLoginsW,
            self._ctypes.byref(mock.sentinel.element_count),
            self._ctypes.byref(mock.sentinel.buff),
            self._ctypes.byref(mock.sentinel.buff_size))

    def test_get_targets(self):
        fake_buff = 'fake\x00buff'
        fake_buff_size = mock.MagicMock()
        fake_buff_size.value = len(fake_buff)

        _get_targets = _utils.get_wrapped_function(
            self._initiator._get_targets)
        resulted_target_list = _get_targets(
            self._initiator,
            forced_update=mock.sentinel.forced_update,
            buff_size=fake_buff_size,
            buff=fake_buff)

        self._mock_run.assert_called_once_with(
            self._iscsidsc.ReportIScsiTargetsW,
            mock.sentinel.forced_update,
            self._ctypes.byref(fake_buff_size),
            self._ctypes.byref(fake_buff))
        self.assertEqual(['fake', 'buff'], resulted_target_list)

    def test_get_iscsi_initiator(self):
        self._ctypes.c_wchar = mock.MagicMock()
        fake_buff = (self._ctypes.c_wchar * (
            iscsi_struct.MAX_ISCSI_NAME_LEN + 1))()
        fake_buff.value = mock.sentinel.buff_value

        resulted_iscsi_initiator = self._initiator.get_iscsi_initiator()

        self._mock_run.assert_called_once_with(
            self._iscsidsc.GetIScsiInitiatorNodeNameW,
            self._ctypes.byref(fake_buff))
        self.assertEqual(mock.sentinel.buff_value, resulted_iscsi_initiator)

    @mock.patch.object(ctypes, 'byref')
    @mock.patch.object(iscsi_struct, 'ISCSI_UNIQUE_CONNECTION_ID')
    @mock.patch.object(iscsi_struct, 'ISCSI_UNIQUE_SESSION_ID')
    def test_login_iscsi_target(self, mock_cls_ISCSI_UNIQUE_SESSION_ID,
                                mock_cls_ISCSI_UNIQUE_CONNECTION_ID,
                                mock_byref):
        self.patch_ctypes.stop()
        fake_target_name = 'fake_target_name'

        resulted_session_id, resulted_conection_id = (
            self._initiator._login_iscsi_target(fake_target_name))

        args_list = self._mock_run.call_args_list[0][0]

        self.assertIsInstance(args_list[1], ctypes.c_wchar_p)
        self.assertEqual(fake_target_name, args_list[1].value)
        self.assertIsInstance(args_list[4], ctypes.c_ulong)
        self.assertEqual(
            ctypes.c_ulong(iscsi_struct.ISCSI_ANY_INITIATOR_PORT).value,
            args_list[4].value)
        self.assertIsInstance(args_list[6], ctypes.c_ulonglong)
        self.assertEqual(iscsi_struct.ISCSI_DEFAULT_SECURITY_FLAGS,
                         args_list[6].value)
        self.assertIsInstance(args_list[9], ctypes.c_ulong)
        self.assertEqual(0, args_list[9].value)

        mock_byref.assert_has_calls([
            mock.call(mock_cls_ISCSI_UNIQUE_SESSION_ID.return_value),
            mock.call(mock_cls_ISCSI_UNIQUE_CONNECTION_ID.return_value)])
        self.assertEqual(
            mock_cls_ISCSI_UNIQUE_SESSION_ID.return_value,
            resulted_session_id)
        self.assertEqual(
            mock_cls_ISCSI_UNIQUE_CONNECTION_ID.return_value,
            resulted_conection_id)

    def test_get_iscsi_sessions(self):
        _get_iscsi_sessions = _utils.get_wrapped_function(
            self._initiator._get_iscsi_sessions)
        _get_iscsi_sessions(
            self._initiator,
            buff=mock.sentinel.buff,
            buff_size=mock.sentinel.buff_size,
            element_count=mock.sentinel.element_count)

        self._mock_run.assert_called_once_with(
            self._iscsidsc.GetIScsiSessionListW,
            self._ctypes.byref(mock.sentinel.buff_size),
            self._ctypes.byref(mock.sentinel.element_count),
            self._ctypes.byref(mock.sentinel.buff))

    @mock.patch.object(iscsi_utils.ISCSIInitiatorUtils,
                       '_get_iscsi_sessions')
    def _test_get_iscsi_target_sessions(self, mock_get_iscsi_sessions,
                                        target_sessions_found=True):
        fake_session = mock.MagicMock()
        fake_session.TargetNodeName = mock.sentinel.target_name
        if target_sessions_found:
            mock_get_iscsi_sessions.return_value = [fake_session]
            expected_tgt_session = [fake_session]
        else:
            mock_get_iscsi_sessions.return_value = []
            expected_tgt_session = []

        resulted_tgt_sessions = self._initiator._get_iscsi_target_sessions(
            mock.sentinel.target_name)

        self.assertEqual(expected_tgt_session, resulted_tgt_sessions)

    def test_get_iscsi_target_sessions(self):
        self._test_get_iscsi_target_sessions()

    def test_get_inexistent_iscsi_target_sessions(self):
        self._test_get_iscsi_target_sessions(target_sessions_found=False)

    def test_get_iscsi_session_devices(self):
        _get_iscsi_session_devices = _utils.get_wrapped_function(
            self._initiator._get_iscsi_session_devices)
        _get_iscsi_session_devices(
            self._initiator,
            mock.sentinel.session_id,
            buff=mock.sentinel.buff,
            element_count=mock.sentinel.element_count)

        self._mock_run.assert_called_once_with(
            self._iscsidsc.GetDevicesForIScsiSessionW,
            self._ctypes.byref(mock.sentinel.session_id),
            self._ctypes.byref(mock.sentinel.element_count),
            self._ctypes.byref(mock.sentinel.buff))

    @mock.patch.object(iscsi_utils.ISCSIInitiatorUtils,
                       '_get_iscsi_session_devices')
    def _test_get_iscsi_session_luns(self, mock_get_iscsi_session_devices,
                                     session_luns_found=True):
        fake_device = mock.MagicMock()
        if session_luns_found:
            mock_get_iscsi_session_devices.return_value = [fake_device]
            expected_luns = [fake_device.ScsiAddress.Lun]
        else:
            mock_get_iscsi_session_devices.return_value = []
            expected_luns = []

        resulted_luns = self._initiator._get_iscsi_session_luns(
            mock.sentinel.session_id)

        mock_get_iscsi_session_devices.assert_called_once_with(
            mock.sentinel.session_id)
        self.assertEqual(expected_luns, resulted_luns)

    def test_get_iscsi_session_luns(self):
        self._test_get_iscsi_session_luns()

    def test_get_inexistent_iscsi_session_luns(self):
        self._test_get_iscsi_session_luns(session_luns_found=False)

    @mock.patch.object(iscsi_utils.ISCSIInitiatorUtils,
                       '_get_iscsi_target_sessions')
    @mock.patch.object(iscsi_utils.ISCSIInitiatorUtils,
                       '_ensure_lun_available')
    @mock.patch.object(iscsi_utils.ISCSIInitiatorUtils,
                       '_get_iscsi_session_devices')
    def _test_get_device_number_for_target(self,
                                           mock_get_iscsi_session_devices,
                                           mock_ensure_lun_available,
                                           mock_get_iscsi_target_sessions,
                                           device_number_found=True):
        fake_sessions = mock.MagicMock()
        fake_device = mock.MagicMock()
        fake_sessions.SessionId = mock.sentinel.sid
        fake_device.ScsiAddress.Lun = mock.sentinel.target_lun
        mock_get_iscsi_target_sessions.return_value = [fake_sessions]

        if device_number_found:
            mock_get_iscsi_session_devices.return_value = [fake_device]
            expected_device_number = (
                fake_device.StorageDeviceNumber.DeviceNumber)
        else:
            mock_get_iscsi_session_devices.return_value = []
            expected_device_number = None

        resulted_device_number = self._initiator.get_device_number_for_target(
            mock.sentinel.target_name,
            mock.sentinel.target_lun)

        mock_get_iscsi_target_sessions.assert_called_once_with(
            mock.sentinel.target_name)
        mock_ensure_lun_available.assert_called_once_with(
            mock.sentinel.sid,
            mock.sentinel.target_name,
            mock.sentinel.target_lun)
        mock_get_iscsi_session_devices.assert_called_once_with(
            mock.sentinel.sid)
        self.assertEqual(expected_device_number, resulted_device_number)

    def test_get_device_number_for_target(self):
        self._test_get_device_number_for_target()

    def test_get_inexistent_device_number_for_target(self):
        self._test_get_device_number_for_target(device_number_found=False)

    @mock.patch.object(iscsi_utils.ISCSIInitiatorUtils,
                       '_get_iscsi_target_sessions')
    @mock.patch.object(iscsi_utils.ISCSIInitiatorUtils,
                       '_get_iscsi_session_devices')
    def _test_get_target_lun_count(self, mock_get_iscsi_session_devices,
                                   mock_get_iscsi_target_sessions,
                                   lun_found=True):
        fake_device = mock.MagicMock()
        fake_session = mock.MagicMock()
        fake_device.StorageDeviceNumber.DeviceType = (
            iscsi_struct.FILE_DEVICE_DISK)
        if not lun_found:
            mock_get_iscsi_target_sessions.return_value = None
            expected_luns_count = 0
        else:
            mock_get_iscsi_target_sessions.return_value = fake_session
            mock_get_iscsi_session_devices.return_value = [fake_device]
            expected_luns_count = 1

        resulted_luns_count = self._initiator.get_target_lun_count(
            mock.sentinel.target_name)

        mock_get_iscsi_target_sessions.assert_called_once_with(
            mock.sentinel.target_name)
        if lun_found:
            mock_get_iscsi_session_devices.assert_called_once_with(
                fake_session[0].SessionId)
        self.assertEqual(expected_luns_count, resulted_luns_count)

    def test_get_target_lun_count(self):
        self._test_get_target_lun_count()

    def test_get_target_lun_not_found(self):
        self._test_get_target_lun_count(lun_found=False)

    @mock.patch.object(ctypes, 'byref')
    def test_send_scsi_report_luns(self, mock_byref):
        self.patch_ctypes.stop()

        _send_scsi_report_luns = _utils.get_wrapped_function(
            self._initiator._send_scsi_report_luns)
        _send_scsi_report_luns(
            self._initiator,
            mock.sentinel.session_id,
            buff=mock.sentinel.buff,
            buff_size=mock.sentinel.buff_size)

        args_list = mock_byref.call_args_list

        scsi_status = args_list[1][0][0]
        sense_buff_size = args_list[4][0][0]
        sense_buff = args_list[5][0][0]

        self.assertIsInstance(scsi_status, ctypes.c_ubyte)
        self.assertIsInstance(sense_buff_size, ctypes.c_ulong)
        self.assertIsInstance(sense_buff,
                              ctypes.c_ubyte * sense_buff_size.value)
        self.assertEqual(0, scsi_status.value)
        self.assertEqual(iscsi_struct.SENSE_BUFF_SIZE, sense_buff_size.value)

        mock_byref.assert_has_calls([
            mock.call(mock.sentinel.session_id),
            mock.call(scsi_status),
            mock.call(mock.sentinel.buff_size),
            mock.call(mock.sentinel.buff),
            mock.call(sense_buff_size),
            mock.call(sense_buff)])

    def test_logout_iscsi_target(self):
        self._initiator._logout_iscsi_target(mock.sentinel.session_id)

        self._mock_run.assert_called_once_with(
            self._iscsidsc.LogoutIScsiTarget,
            self._ctypes.byref(mock.sentinel.session_id))

    @mock.patch.object(iscsi_struct, 'ISCSI_LOGIN_OPTIONS')
    def _test_get_login_opts(self, mock_cls_ISCSI_LOGIN_OPTIONS,
                             auth_type=None):
        auth_username = mock.sentinel.auth_username if not auth_type else None
        auth_password = mock.sentinel.auth_password if not auth_type else None
        auth_type = auth_type if auth_type else (
            iscsi_utils.constants.ISCSI_NO_AUTH_TYPE)

        resulted_login_opts = self._initiator._get_login_opts(
            auth_username, auth_password, auth_type)

        expected_login_opts = mock_cls_ISCSI_LOGIN_OPTIONS.return_value
        mock_cls_ISCSI_LOGIN_OPTIONS.assert_called_once_with(
            Username=auth_username,
            Password=auth_password,
            AuthType=auth_type)
        self.assertEqual(expected_login_opts, resulted_login_opts)

    def test_get_login_opts_without_auth_type(self):
        self._test_get_login_opts()

    def test_get_login_opts_with_auth_type(self):
        self._test_get_login_opts(auth_type=mock.sentinel.auth_type)

    @mock.patch.object(iscsi_utils.ISCSIInitiatorUtils,
                       '_get_login_opts')
    @mock.patch.object(iscsi_struct, 'ISCSI_TARGET_PORTAL')
    @mock.patch.object(iscsi_utils.ISCSIInitiatorUtils, '_update_portal_map')
    @mock.patch.object(iscsi_utils.ISCSIInitiatorUtils, '_add_target_portal')
    @mock.patch.object(iscsi_utils.ISCSIInitiatorUtils,
                       '_get_iscsi_target_sessions')
    @mock.patch.object(iscsi_utils.ISCSIInitiatorUtils, '_get_targets')
    @mock.patch.object(iscsi_utils.ISCSIInitiatorUtils,
                       '_refresh_target_portal')
    @mock.patch.object(iscsi_utils.ISCSIInitiatorUtils, '_login_iscsi_target')
    @mock.patch.object(iscsi_utils.ISCSIInitiatorUtils,
                       '_ensure_lun_available')
    def _test_login_storage_target(self, mock_ensure_lun_available,
                                   mock_login_iscsi_target,
                                   mock_refresh_target_portal,
                                   mock_get_targets,
                                   mock_get_iscsi_target_sessions,
                                   mock_add_target_portal,
                                   mock_update_portal_map,
                                   mock_cls_ISCSI_TARGET_PORTAL,
                                   mock_get_login_opts,
                                   sessions_found=True):
        fake_target_portal = '1.1.1.1:1111'
        fake_portal_addr = '1.1.1.1'
        fake_portal_port = 1111
        fake_portal = mock_cls_ISCSI_TARGET_PORTAL.return_value
        fake_login_opts = mock_get_login_opts.return_value

        fake_targets = [mock.sentinel.fake_target]
        fake_sessions = [mock.MagicMock()]
        fake_sessions[0].SessionId = mock.sentinel.SessionId
        mock_get_targets.return_value = fake_targets
        mock_login_iscsi_target.return_value = (mock.sentinel.sid,
                                                mock.sentinel.cid)
        mock_get_iscsi_target_sessions.return_value = (
            sessions_found if not sessions_found else fake_sessions)
        fake_sid = mock.sentinel.SessionId if sessions_found else (
            mock.sentinel.sid)

        self._initiator.login_storage_target(
            mock.sentinel.target_lun,
            mock.sentinel.target_iqn,
            fake_target_portal,
            auth_username=mock.sentinel.auth_username,
            auth_password=mock.sentinel.auth_password,
            auth_type=mock.sentinel.auth_type)

        mock_get_login_opts.assert_called_once_with(
            mock.sentinel.auth_username,
            mock.sentinel.auth_password,
            mock.sentinel.auth_type)
        mock_cls_ISCSI_TARGET_PORTAL.assert_called_once_with(
            Address=fake_portal_addr,
            Socket=fake_portal_port)
        mock_update_portal_map(fake_portal.Address,
                               fake_portal.Socket,
                               mock.sentinel.target_iqn)
        mock_add_target_portal.assert_called_once_with(
            fake_portal, login_opts=None)
        mock_get_iscsi_target_sessions.assert_called_once_with(
            mock.sentinel.target_iqn)
        if not sessions_found:
            mock_get_targets.assert_called_once_with()
            mock_refresh_target_portal.assert_called_once_with(fake_portal)
            mock_login_iscsi_target.assert_has_calls([
                mock.call(mock.sentinel.target_iqn,
                          fake_portal,
                          fake_login_opts,
                          is_persistent=True),
                mock.call(mock.sentinel.target_iqn,
                          fake_portal,
                          fake_login_opts,
                          is_persistent=False)])
        mock_ensure_lun_available.assert_called_once_with(
            fake_sid, mock.sentinel.target_iqn, mock.sentinel.target_lun)

    def test_login_storage_target(self):
        self._test_login_storage_target()

    def test_login_storage_target_without_sessions(self):
        self._test_login_storage_target(sessions_found=False)

    @mock.patch('eventlet.greenthread.sleep')
    @mock.patch.object(iscsi_utils.ISCSIInitiatorUtils,
                       '_get_iscsi_session_luns')
    @mock.patch.object(iscsi_utils.ISCSIInitiatorUtils,
                       '_send_scsi_report_luns')
    def _test_ensure_lun_available(self, mock_send_scsi_report_luns,
                                   mock_get_iscsi_session_luns,
                                   mock_greenthread_sleep,
                                   raised_exception=False):
        max_retry_count = 6
        if raised_exception:
            mock_get_iscsi_session_luns.return_value = []
            self.assertRaises(exceptions.ISCSILunNotAvailable,
                              self._initiator._ensure_lun_available,
                              mock.sentinel.session_id,
                              mock.sentinel.target_iqn,
                              mock.sentinel.target_lun)
            mock_get_iscsi_session_luns.assert_has_calls(
                [mock.call(mock.sentinel.session_id)] * max_retry_count)
            mock_send_scsi_report_luns.assert_has_calls(
                [mock.call(mock.sentinel.session_id)] * max_retry_count)
        else:
            mock_get_iscsi_session_luns.return_value = [
                mock.sentinel.target_lun]
            self._initiator._ensure_lun_available(mock.sentinel.session_id,
                                                  mock.sentinel.target_iqn,
                                                  mock.sentinel.target_lun)
            mock_get_iscsi_session_luns.assert_called_once_with(
                mock.sentinel.session_id)

    def test_ensure_lun_available(self):
        self._test_ensure_lun_available()

    def test_ensure_lun_available_fail(self):
        self._test_ensure_lun_available(raised_exception=True)

    @mock.patch.object(iscsi_utils.ISCSIInitiatorUtils,
                       '_get_iscsi_target_sessions')
    @mock.patch.object(iscsi_utils.ISCSIInitiatorUtils,
                       '_logout_iscsi_target')
    @mock.patch.object(iscsi_utils.ISCSIInitiatorUtils,
                       '_remove_target_persistent_logins')
    @mock.patch.object(iscsi_utils.ISCSIInitiatorUtils,
                       '_get_portals_exporting_target')
    @mock.patch.object(iscsi_utils.ISCSIInitiatorUtils, '_update_portal_map')
    @mock.patch.object(iscsi_utils.ISCSIInitiatorUtils, '_portal_in_use')
    @mock.patch.object(iscsi_utils.ISCSIInitiatorUtils,
                       '_remove_target_portal')
    def _test_logout_storage_target(self, mock_remove_target_portal,
                                    mock_portal_in_use, mock_update_portal_map,
                                    mock_get_portals_exporting_target,
                                    mock_remove_target_persistent_logins,
                                    mock_logout_iscsi_target,
                                    mock_get_iscsi_target_sessions,
                                    sessions_found=True,
                                    portals_found=True):
        fake_session = mock.MagicMock()
        fake_session.SessionId = mock.sentinel.sid
        fake_sessions = [fake_session]
        fake_portal = mock.MagicMock()
        fake_portals = [fake_portal]

        mock_get_iscsi_target_sessions.return_value = (
            fake_sessions if sessions_found else [])
        mock_get_portals_exporting_target.return_value = (
            fake_portals if portals_found else [])
        mock_portal_in_use.return_value = False

        self._initiator.logout_storage_target(mock.sentinel.target_iqn)

        mock_get_iscsi_target_sessions.assert_called_once_with(
            mock.sentinel.target_iqn)
        if sessions_found:
            mock_logout_iscsi_target.assert_called_once_with(mock.sentinel.sid)
        mock_remove_target_persistent_logins.assert_called_once_with(
            mock.sentinel.target_iqn)
        mock_get_portals_exporting_target.assert_called_once_with(
            mock.sentinel.target_iqn)
        if portals_found:
            mock_update_portal_map.assert_called_once_with(
                fake_portal.Address,
                fake_portal.Socket,
                mock.sentinel.target_iqn,
                remove=True)
            mock_portal_in_use.assert_called_once_with(
                fake_portal.Address, fake_portal.Socket)
            mock_remove_target_portal.assert_called_once_with(fake_portal)

    def test_logout_storage_target_no_sessions(self):
        self._test_logout_storage_target(sessions_found=False)

    def test_logout_storage_target_no_portals(self):
        self._test_logout_storage_target(portals_found=False)

    @mock.patch.object(iscsi_utils.ISCSIInitiatorUtils,
                       '_remove_persistent_login')
    @mock.patch.object(iscsi_utils.ISCSIInitiatorUtils,
                       '_get_iscsi_persistent_logins')
    def _test_remove_target_persistent_logins(self,
                                              mock_get_iscsi_persistent_logins,
                                              mock_remove_persistent_login,
                                              target_iqn_is_persistent=False):
        fake_persistent_login = mock.MagicMock()
        fake_persistent_login.TargetName = mock.sentinel.target_iqn
        mock_get_iscsi_persistent_logins.return_value = (
            [fake_persistent_login] if target_iqn_is_persistent else [])

        self._initiator._remove_target_persistent_logins(
            mock.sentinel.target_iqn)

        if target_iqn_is_persistent:
            mock_remove_persistent_login.assert_called_once_with(
                fake_persistent_login)
        mock_get_iscsi_persistent_logins.assert_called_once_with()

    def test_remove_target_persistent_logins(self):
        self._test_remove_target_persistent_logins(
            target_iqn_is_persistent=True)

    def test_remove_target_without_persistent_logins(self):
        self._test_remove_target_persistent_logins()

    @mock.patch.object(ctypes, 'byref')
    def test_remove_persistent_login(self, mock_byref):
        self.patch_ctypes.stop()
        fake_persistent_login = mock.MagicMock()
        fake_persistent_login.InitiatorInstance = 'fake_persistent_login'
        fake_persistent_login.TargetName = 'fake_target_name'

        self._initiator._remove_persistent_login(fake_persistent_login)

        args_list = self._mock_run.call_args_list[0][0]
        self.assertIsInstance(args_list[1], ctypes.c_wchar_p)
        self.assertEqual(fake_persistent_login.InitiatorInstance,
                         args_list[1].value)
        self.assertIsInstance(args_list[3], ctypes.c_wchar_p)
        self.assertEqual(fake_persistent_login.TargetName,
                         args_list[3].value)
        mock_byref.assert_called_once_with(fake_persistent_login.TargetPortal)
