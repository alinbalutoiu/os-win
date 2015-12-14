# Copyright 2015 Cloudbase Solutions Srl
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

import mock
from oslotest import base

from os_win import _utils
from os_win import exceptions
from os_win.utils.storage.initiator import fc_structures as fc_struct
from os_win.utils.storage.initiator import fc_utils


class FCUtilsTestCase(base.BaseTestCase):
    """Unit tests for the Hyper-V FCUtils class."""

    _FAKE_ADAPTER_NAME = 'fake_adapter_name'
    _FAKE_ADAPTER_WWN = [1]

    @mock.patch.object(fc_utils, 'wmi', create=True)
    def setUp(self, mock_wmi):
        super(FCUtilsTestCase, self).setUp()
        self._setup_lib_mocks()

        self._fc_utils = fc_utils.FCUtils()
        self._run_mocker = mock.patch.object(self._fc_utils,
                                             '_run_and_check_output')
        self._run_mocker.start()

        self._mock_run = self._fc_utils._run_and_check_output

        self.addCleanup(mock.patch.stopall)

    def _setup_lib_mocks(self):
        self._ctypes = mock.Mock()
        # This is used in order to easily make assertions on the variables
        # passed by reference.
        self._ctypes.byref = lambda x: (x, "byref")

        mock.patch.object(fc_utils, 'hbaapi', create=True).start()
        self._ctypes_mocker = mock.patch.object(fc_utils, 'ctypes',
                                                self._ctypes)
        self._ctypes_mocker.start()

    def _test_run_and_check_output(self, *args, **kwargs):
        self._run_mocker.stop()
        with mock.patch.object(fc_utils.win32utils.Win32Utils,
                               'run_and_check_output') as mock_win32_run:
            self._fc_utils._run_and_check_output(*args, **kwargs)

            mock_win32_run.assert_called_once_with(
                failure_exc=exceptions.FCWin32Exception, *args, **kwargs)

    def test_run_and_check_output_without_args(self):
        self._test_run_and_check_output(adapter_name=self._FAKE_ADAPTER_NAME)

    def test_run_and_check_output_with_args(self):
        self._test_run_and_check_output()

    def _test_open_adapter(self, adapter_name=None, adapter_wwn=None):
        self._ctypes_mocker.stop()
        self._mock_run.return_value = mock.sentinel.handle

        if adapter_name:
            func = fc_utils.hbaapi.HBA_OpenAdapter
            arg = fc_utils.ctypes.c_char_p(adapter_name)
        elif adapter_wwn:
            func = fc_utils.hbaapi.HBA_OpenAdapterByWWN
            arg = fc_utils.fc_struct.HBA_WWN(*adapter_wwn)

        if adapter_name or adapter_wwn:
            resulted_handle = self._fc_utils._open_adapter(
                adapter_name=adapter_name, adapter_wwn=adapter_wwn)

            list_args = self._mock_run.call_args_list[0][0]
            self.assertEqual(func, list_args[0])
            if adapter_name:
                self.assertEqual(adapter_name, list_args[1].value)
            else:
                self.assertEqual(
                    fc_utils.ctypes.cast(
                        arg,
                        fc_utils.ctypes.POINTER(
                            fc_utils.ctypes.c_ubyte))[0],
                    fc_utils.ctypes.cast(
                        list_args[1],
                        fc_utils.ctypes.POINTER(
                            fc_utils.ctypes.c_ubyte))[0]
                                )

            self.assertEqual(mock.sentinel.handle, resulted_handle)
        else:
            self.assertRaises(exceptions.FCException,
                              self._fc_utils._open_adapter,
                              adapter_name,
                              adapter_wwn)

    def test_adapter_by_name(self):
        self._test_open_adapter(adapter_name=self._FAKE_ADAPTER_NAME)

    def test_adapter_by_wwn(self):
        self._test_open_adapter(adapter_wwn=self._FAKE_ADAPTER_WWN)

    def test_open_adapter_not_specified(self):
        self._test_open_adapter()

    def test_close_adapter(self):
        self._fc_utils._close_adapter(mock.sentinel.hba_handle)
        fc_utils.hbaapi.HBA_CloseAdapter.assert_called_once_with(
            mock.sentinel.hba_handle)

    @mock.patch.object(fc_utils.FCUtils, '_open_adapter')
    @mock.patch.object(fc_utils.FCUtils, '_close_adapter')
    def _test_get_hba_handle(self, mock_close_adapter,
                             mock_open_adapter, *args, **kwargs):
        with self._fc_utils._get_hba_handle(*args, **kwargs):
            mock_open_adapter.assert_called_once_with(*args, **kwargs)
        mock_close_adapter.assert_called_once_with(
            mock_open_adapter.return_value)

    def test_get_hba_handle_with_params(self):
        self._test_get_hba_handle(adapter_name=self._FAKE_ADAPTER_NAME)

    def test_get_hba_handle_without_params(self):
        self._test_get_hba_handle()

    def test_get_adapter_name(self):
        self._ctypes_mocker.stop()
        fake_adapter_index = 1
        fake_updated_buff = ''
        fake_empty_buff = '\x00'

        resulted_adapter_name = self._fc_utils._get_adapter_name(
            fake_adapter_index)

        list_args = self._mock_run.call_args_list[0][0]

        self.assertEqual(fc_utils.hbaapi.HBA_GetAdapterName,
                         list_args[0])
        self.assertEqual(fc_utils.ctypes.c_uint32(fake_adapter_index).value,
                         list_args[1].value)
        self.assertEqual(
            fake_empty_buff,
            fc_utils.ctypes.cast(
                list_args[2], fc_utils.ctypes.POINTER(
                    fc_utils.ctypes.c_char)
                                ).contents.value)
        self.assertEqual(fake_updated_buff, resulted_adapter_name)

    @mock.patch.object(fc_struct, 'get_target_mapping_struct')
    def test_get_target_mapping(self, mock_get_target_mapping_struct):
        side_effect = [fc_utils.HBA_STATUS_ERROR_MORE_DATA] * 2
        side_effect.append(fc_utils.HBA_STATUS_OK)
        self._mock_run.side_effect = side_effect
        mock_mapping = mock_get_target_mapping_struct.return_value

        resulted_mapping = self._fc_utils._get_target_mapping(
            mock.sentinel.hba_handle)

        expected_calls = [
            mock.call(fc_utils.hbaapi.HBA_GetFcpTargetMapping,
                      mock.sentinel.hba_handle,
                      self._ctypes.byref(mock_mapping),
                      ignored_error_codes=[fc_utils.HBA_STATUS_ERROR_MORE_DATA]
                      )] * 3

        self._mock_run.assert_has_calls(expected_calls)

        self.assertEqual(mock_mapping, resulted_mapping)

    @mock.patch.object(fc_struct, 'HBA_PortAttributes')
    def test_get_adapter_port_attributes(self, mock_class_HBA_PortAttributes):
        resulted_port_attributes = self._fc_utils._get_adapter_port_attributes(
            mock.sentinel.hba_handle, mock.sentinel.port_index)

        self._mock_run.assert_called_once_with(
            fc_utils.hbaapi.HBA_GetAdapterPortAttributes,
            mock.sentinel.hba_handle,
            mock.sentinel.port_index,
            self._ctypes.byref(mock_class_HBA_PortAttributes.return_value))

        self.assertEqual(mock_class_HBA_PortAttributes.return_value,
                         resulted_port_attributes)

    @mock.patch.object(fc_struct, 'HBA_AdapterAttributes')
    def test_get_adapter_attributes(self, mock_class_HBA_AdapterAttributes):
        self._ctypes_mocker.stop()
        fake_ctype_value = fc_utils.ctypes.c_char('c')
        mock_class_HBA_AdapterAttributes.return_value = fake_ctype_value
        resulted_hba_attributes = self._fc_utils._get_adapter_attributes(
            mock.sentinel.hba_handle)

        list_args = self._mock_run.call_args_list[0][0]

        self.assertEqual(fc_utils.hbaapi.HBA_GetAdapterAttributes,
                         list_args[0])
        self.assertEqual(mock.sentinel.hba_handle, list_args[1])
        self.assertEqual(
            fake_ctype_value.value,
            fc_utils.ctypes.cast(
                list_args[2], fc_utils.ctypes.POINTER(
                    fc_utils.ctypes.c_char)
                                ).contents.value)

        self.assertEqual(mock_class_HBA_AdapterAttributes.return_value,
                         resulted_hba_attributes)

    @mock.patch.object(fc_utils.FCUtils, 'get_fc_hba_count')
    def test_get_fc_hba_ports_missing_hbas(self, mock_get_fc_hba_count):
        mock_get_fc_hba_count.return_value = 0

        resulted_hba_ports = self._fc_utils.get_fc_hba_ports()

        self.assertEqual([], resulted_hba_ports)

    @mock.patch.object(fc_utils.FCUtils, '_open_adapter')
    @mock.patch.object(fc_utils.FCUtils, '_close_adapter')
    @mock.patch.object(fc_utils.FCUtils, '_get_adapter_port_attributes')
    @mock.patch.object(fc_utils.FCUtils, '_get_adapter_attributes')
    @mock.patch.object(fc_utils.FCUtils, '_get_adapter_name')
    @mock.patch.object(fc_utils.FCUtils, 'get_fc_hba_count')
    def test_get_fc_hba_ports(self, mock_get_fc_hba_count,
                              mock_get_adapter_name,
                              mock_get_adapter_attributes,
                              mock_get_adapter_port_attributes,
                              mock_close_adapter,
                              mock_open_adapter):
        FAKE_PORT_COUNT = 1
        FAKE_PORT_INDEX = 0
        FAKE_ADAPTER_COUNT = 1
        FAKE_ADAPTER_INDEX = 0
        FAKE_NODE_WWN = [1, 2, 3]
        FAKE_PORT_WWN = [1, 2, 3]

        mock_adapter_attributes = mock.MagicMock()
        mock_port_attributes = mock.MagicMock()

        mock_port_attributes.NodeWWN = FAKE_NODE_WWN
        mock_port_attributes.PortWWN = FAKE_PORT_WWN
        mock_get_fc_hba_count.return_value = FAKE_ADAPTER_COUNT
        mock_adapter_attributes.NumberOfPorts = FAKE_PORT_COUNT
        mock_get_adapter_attributes.return_value = mock_adapter_attributes
        mock_get_adapter_port_attributes.return_value = mock_port_attributes

        resulted_hba_ports = self._fc_utils.get_fc_hba_ports()

        expected_hba_ports = [{
            'node_name': self._fc_utils._wwn_array_to_hex_str(FAKE_NODE_WWN),
            'port_name': self._fc_utils._wwn_array_to_hex_str(FAKE_PORT_WWN)
        }]
        self.assertEqual(expected_hba_ports, resulted_hba_ports)
        mock_get_adapter_name.assert_called_with(FAKE_ADAPTER_INDEX)
        mock_open_adapter.assert_called_once_with(
            adapter_name=mock_get_adapter_name.return_value)
        mock_close_adapter.assert_called_once_with(
            mock_open_adapter(mock_get_adapter_name.return_value))
        mock_get_adapter_attributes.assert_called_once_with(
            mock_open_adapter.return_value)
        mock_get_adapter_port_attributes.assert_called_once_with(
            mock_open_adapter.return_value, FAKE_PORT_INDEX)

    @mock.patch.object(fc_utils.FCUtils, '_open_adapter')
    @mock.patch.object(fc_utils.FCUtils, '_close_adapter')
    @mock.patch.object(fc_utils.FCUtils, '_get_target_mapping')
    def test_get_fc_target_mapping(self, mock_get_target_mapping,
                                   mock_close_adapter, mock_open_adapter,
                                   ):
        FAKE_NODE_WWN_STRING = "123"
        FAKE_NODE_WWN = [1, 2, 3]
        FAKE_PORT_WWN = [1, 2, 3]

        mock_fcp_mappings = mock.MagicMock()
        mock_entry = mock.MagicMock()
        mock_entry.FcpId.NodeWWN = FAKE_NODE_WWN
        mock_entry.FcpId.PortWWN = FAKE_PORT_WWN
        mock_entry.ScsiId.OSDeviceName = mock.sentinel.OSDeviceName
        mock_entry.ScsiId.ScsiOSLun = mock.sentinel.ScsiOSLun
        mock_fcp_mappings.Entries = [mock_entry]
        mock_get_target_mapping.return_value = mock_fcp_mappings
        mock_node_wwn = self._fc_utils._wwn_hex_string_to_array(
            FAKE_NODE_WWN_STRING)

        resulted_mappings = self._fc_utils.get_fc_target_mappings(
            FAKE_NODE_WWN_STRING)

        expected_mappings = [{
            'node_name': self._fc_utils._wwn_array_to_hex_str(FAKE_NODE_WWN),
            'port_name': self._fc_utils._wwn_array_to_hex_str(FAKE_PORT_WWN),
            'device_name': mock.sentinel.OSDeviceName,
            'lun': mock.sentinel.ScsiOSLun
        }]
        self.assertEqual(expected_mappings, resulted_mappings)
        mock_open_adapter.assert_called_once_with(adapter_wwn=mock_node_wwn)
        mock_close_adapter.assert_called_once_with(
            mock_open_adapter.return_value)

    @mock.patch.object(_utils, 'execute')
    def test_rescan_disks(self, mock_execute):
        cmd = ("cmd", "/c", "echo", "rescan", "|", "diskpart.exe")

        self._fc_utils.rescan_disks()

        mock_execute.assert_called_once_with(*cmd)
