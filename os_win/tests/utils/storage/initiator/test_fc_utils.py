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
    _FAKE_ADAPTER_WWN = ['fake_adapter_wwn']

    @mock.patch.object(fc_utils, 'wmi', create=True)
    def setUp(self, mock_wmi):
        super(FCUtilsTestCase, self).setUp()
        self._setup_lib_mocks()

        self._fc_utils = fc_utils.FCUtils()
        self._fc_utils._conn_wmi = mock.MagicMock()
        self._fc_utils._conn_cimv2 = mock.MagicMock()
        self._fc_utils._win32_utils = mock.Mock()

        self._mock_run = self._fc_utils._win32_utils.run_and_check_output

        self.addCleanup(mock.patch.stopall)

    def _setup_lib_mocks(self):
        self._ctypes = mock.Mock()
        # This is used in order to easily make assertions on the variables
        # passed by reference.
        self._ctypes.byref = lambda x: (x, "byref")
        self._ctypes.c_char_p = lambda x: (x, "c_char_p")
        self._ctypes.c_uint32 = lambda x: (x, "c_uint32")

        mock.patch.multiple(fc_utils, ctypes=self._ctypes,
                            hbaapi=mock.DEFAULT, create=True).start()

    def test_run_and_check_output(self):
        self._fc_utils._win32_utils.run_and_check_output.return_value = (
            mock.sentinel.FAKE_OUTPUT)

        ret_val = self._fc_utils._run_and_check_output(
            mock.sentinel.args)

        self.assertEqual(mock.sentinel.FAKE_OUTPUT, ret_val)

    @mock.patch.object(fc_struct, 'HBA_WWN')
    def _test_open_adapter(self, mock_hba_wwn, adapter_name=None,
                           adapter_wwn=None, raised_exc=None):
        self._mock_run.return_value = mock.sentinel.FAKE_HANDLER

        if adapter_name:
            func = fc_utils.hbaapi.HBA_OpenAdapter
            arg = self._ctypes.c_char_p(adapter_name)
        elif adapter_wwn:
            func = fc_utils.hbaapi.HBA_OpenAdapterByWWN
            arg = mock_hba_wwn.return_value

        if not raised_exc:
            resulted_handler = self._fc_utils._open_adapter(adapter_name,
                                                            adapter_wwn)
            self._mock_run.assert_called_once_with(
                func,
                arg,
                ret_val_is_err_code=False,
                error_on_nonzero_ret_val=False,
                error_ret_vals=[0],
                failure_exc=exceptions.FCWin32Exception)
            self.assertEqual(mock.sentinel.FAKE_HANDLER, resulted_handler)
            if adapter_wwn:
                mock_hba_wwn.assert_called_once_with(*adapter_wwn)
        else:
            self.assertRaises(raised_exc,
                              self._fc_utils._open_adapter,
                              adapter_name,
                              adapter_wwn)

    def test_open_adapter_with_name(self):
        self._test_open_adapter(adapter_name=self._FAKE_ADAPTER_NAME)

    def test_open_adapter_with_wwn(self):
        self._test_open_adapter(adapter_wwn=self._FAKE_ADAPTER_WWN)

    def test_open_adapter_not_specified(self):
        self._test_open_adapter(raised_exc=exceptions.FCException)

    def test_close_adapter(self):
        self._fc_utils._close_adapter(mock.sentinel.FAKE_HBA_HANDLE)
        fc_utils.hbaapi.HBA_CloseAdapter.assert_called_once_with(
            mock.sentinel.FAKE_HBA_HANDLE)

    @mock.patch.object(fc_utils.FCUtils, '_open_adapter')
    @mock.patch.object(fc_utils.FCUtils, '_close_adapter')
    def test_get_hba_handle(self, mock_close_adapter, mock_open_adapter):
        with self._fc_utils._get_hba_handle():
            pass
        mock_open_adapter.assert_called_once_with()
        mock_close_adapter.assert_called_once_with(
            mock_open_adapter.return_value)

    @mock.patch.object(fc_utils.FCUtils, '_run_and_check_output')
    def test_get_adapter_name(self, mock_run_and_check_output):
        self._ctypes.c_char = mock.MagicMock()
        mock_buff = (self._ctypes.c_char * 256)()

        resulted_name = self._fc_utils._get_adapter_name(
            mock.sentinel.FAKE_ADAPTER_INDEX)

        mock_run_and_check_output.assert_called_once_with(
            fc_utils.hbaapi.HBA_GetAdapterName,
            self._ctypes.c_uint32(mock.sentinel.FAKE_ADAPTER_INDEX),
            self._ctypes.byref(mock_buff))
        self.assertEqual(resulted_name, mock_buff[:].strip('\x00'))

    @mock.patch.object(fc_struct, 'get_target_mapping_struct')
    @mock.patch.object(fc_utils.FCUtils, '_run_and_check_output')
    def test_get_target_mapping(self, mock_run_and_check_output,
                                mock_get_target_mapping_struct):
        mock_mapping = mock.MagicMock()
        mock_run_and_check_output.return_value = fc_utils.HBA_STATUS_OK
        mock_get_target_mapping_struct.return_value = mock_mapping

        resulted_mapping = self._fc_utils._get_target_mapping(
            mock.sentinel.hba_handle)

        mock_run_and_check_output.assert_called_once_with(
            fc_utils.hbaapi.HBA_GetFcpTargetMapping,
            mock.sentinel.hba_handle,
            self._ctypes.byref(mock_mapping),
            ignored_error_codes=[fc_utils.HBA_STATUS_ERROR_MORE_DATA])

        self.assertEqual(mock_mapping, resulted_mapping)

    @mock.patch.object(fc_struct, 'HBA_AdapterAttributes')
    @mock.patch.object(fc_utils.FCUtils, '_run_and_check_output')
    def test_get_adapter_port_attributes(self, mock_run_and_check_output,
                                         mock_class_HBA_AdapterAttributes):
        resulted_hba_attributes = self._fc_utils._get_adapter_attributes(
            mock.sentinel.hba_handle)

        mock_run_and_check_output.assert_called_once_with(
            fc_utils.hbaapi.HBA_GetAdapterAttributes,
            mock.sentinel.hba_handle,
            self._ctypes.byref(mock_class_HBA_AdapterAttributes()))

        self.assertEqual(mock_class_HBA_AdapterAttributes(),
                         resulted_hba_attributes)

    @mock.patch.object(fc_utils.FCUtils, 'get_fc_hba_count')
    def test_get_fc_hba_ports_empty(self, mock_get_fc_hba_count):
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
