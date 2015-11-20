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
import inspect
import sys

if sys.platform == 'win32':
    iscsidsc = ctypes.windll.iscsidsc
    from os_win.utils.storage.initiator import (
        iscsidsc_structures as iscsi_struct)

import decorator
from oslo_log import log as logging
from oslo_service import loopingcall

from os_win._i18n import _LI
from os_win import _utils
from os_win import exceptions
from os_win.utils import constants
from os_win.utils.storage.initiator import iscsierr
from os_win.utils import win32utils


LOG = logging.getLogger(__name__)

ERROR_INSUFFICIENT_BUFFER = 0x7a


def ensure_buff_and_retrieve_items(struct_type=None,
                                   func_requests_buff_sz=True,
                                   parse_output=True,
                                   buff_type = ctypes.c_ubyte):
    @decorator.decorator
    def wrapper(f, *args, **kwargs):
        call_args = inspect.getcallargs(f, *args, **kwargs)
        call_args['element_count'] = ctypes.c_ulong(0)
        call_args['buff'] = (buff_type * 0)()
        call_args['buff_size'] = ctypes.c_ulong(0)

        while True:
            try:
                ret_val = f(**call_args)
                if parse_output:
                    return _get_items_from_buff(
                        call_args['buff'],
                        struct_type,
                        call_args['element_count'].value)
                else:
                    return ret_val
            except exceptions.Win32Exception as ex:
                if (ex.error_code & 0xFFFF) == ERROR_INSUFFICIENT_BUFFER:
                    if func_requests_buff_sz:
                        buff_size = call_args['buff_size'].value
                    else:
                        buff_size = (ctypes.sizeof(struct_type) *
                                     call_args['element_count'].value)
                    call_args['buff'] = (buff_type * buff_size)()
                else:
                    raise
    return wrapper


def _get_items_from_buff(buff, item_type, element_count):
    array_type = item_type * element_count
    return ctypes.cast(buff, ctypes.POINTER(array_type)).contents


def portal_synchronized(f):
    def wrapper(inst, target_addr, target_port, *args, **kwargs):
        lock_name = '%s:%s' % (target_addr, target_port)

        @_utils.synchronized(lock_name)
        def inner():
            return f(inst, target_addr, target_port, *args, **kwargs)
        return inner()
    return wrapper


portal_map = collections.defaultdict(set)


class ISCSIInitiatorUtils(object):
    # TODO(lpetrut): document method params as some of them
    # accept specific structures.
    def __init__(self):
        self._win32utils = win32utils.Win32Utils()
        self._refresh_used_portals()

    @portal_synchronized
    def _update_portal_map(self, target_addr, target_port, target_iqn,
                           remove=False):
        portal = "%s:%s" % (target_addr, target_port)
        if remove:
            if target_iqn in portal_map[portal]:
                portal_map[portal].remove(target_iqn)
            if not portal_map[portal]:
                del portal_map[portal]
        else:
            portal_map[portal].add(target_iqn)

    @portal_synchronized
    def _portal_in_use(self, target_addr, target_port):
        portal = "%s:%s" % (target_addr, target_port)
        return portal in portal_map

    def _refresh_used_portals(self):
        sessions = self._get_iscsi_sessions()
        for session in sessions:
            connections = session.Connections[:session.ConnectionCount]
            for conn in connections:
                self._update_portal_map(conn.TargetAddress,
                                        conn.TargetSocket,
                                        session.TargetNodeName)

        persistent_logins = self._get_iscsi_persistent_logins()
        for login_info in persistent_logins:
            portal = login_info.TargetPortal
            self._update_portal_map(portal.Address,
                                    portal.Socket,
                                    login_info.TargetName)

    def _run_and_check_output(self, *args, **kwargs):
        kwargs['error_msg_src'] = iscsierr.err_msg_dict
        self._win32utils.run_and_check_output(*args, **kwargs)

    def _add_target_portal(self, portal, login_opts=None):
        # Note(lpetrut): CHAP credentials may be passed at this point.
        # Some HP SANs required this if CHAP was enabled, but seems
        # to cause issues with other backends.
        ignored_error_codes = [iscsierr.ISDSC_INITIATOR_NODE_ALREADY_EXISTS]
        login_opts_ref = ctypes.byref(login_opts) if login_opts else None
        self._run_and_check_output(
            iscsidsc.AddIScsiSendTargetPortalW,
            None,
            ctypes.c_ulong(iscsi_struct.ISCSI_ALL_INITIATOR_PORTS),
            login_opts_ref,
            ctypes.c_ulonglong(iscsi_struct.ISCSI_DEFAULT_SECURITY_FLAGS),
            ctypes.byref(portal),
            ignored_error_codes=ignored_error_codes)

    def _remove_target_portal(self, portal, ignore_missing=True):
        ignored_error_codes = [iscsierr.ISDSC_PORTAL_NOT_FOUND]

        self._run_and_check_output(
            iscsidsc.RemoveIScsiSendTargetPortalW,
            None,
            ctypes.c_ulong(iscsi_struct.ISCSI_ALL_INITIATOR_PORTS),
            ctypes.byref(portal),
            ignored_error_codes=ignored_error_codes)

    def _refresh_target_portal(self, portal, symbolic_name=None):
        # Performs the 'SendTarget' command, updating the list
        # of available iSCSI targets
        self._run_and_check_output(
            iscsidsc.RefreshIScsiSendTargetPortalW,
            None,
            ctypes.c_ulong(iscsi_struct.ISCSI_ALL_INITIATOR_PORTS),
            ctypes.byref(portal))

    @ensure_buff_and_retrieve_items(
        func_requests_buff_sz=False,
        struct_type=iscsi_struct.ISCSI_TARGET_PORTAL)
    def _get_portals_exporting_target(self, target_name,
                                      buff=None, buff_size=None,
                                      element_count=None):
        self._run_and_check_output(
            iscsidsc.ReportIScsiTargetPortalsW,
            None,
            ctypes.c_wchar_p(target_name),
            None,
            ctypes.byref(element_count),
            ctypes.byref(buff))

    @ensure_buff_and_retrieve_items(
        struct_type=iscsi_struct.PERSISTENT_ISCSI_LOGIN_INFO)
    def _get_iscsi_persistent_logins(self, buff=None, buff_size=None,
                                     element_count=None):
        self._run_and_check_output(
            iscsidsc.ReportIScsiPersistentLoginsW,
            ctypes.byref(element_count),
            ctypes.byref(buff),
            ctypes.byref(buff_size))

    @ensure_buff_and_retrieve_items(
        buff_type=ctypes.c_wchar,
        parse_output=False)
    def _get_targets(self, forced_update=False, buff=None,
                     buff_size=None, element_count=None):
        """Get the list of iSCSI targets seen by the initiator service."""
        self._run_and_check_output(
            iscsidsc.ReportIScsiTargetsW,
            forced_update,
            ctypes.byref(buff_size),
            ctypes.byref(buff))

        tgt_list = buff[:buff_size.value].strip('\x00').split('\x00')
        return tgt_list

    def get_iscsi_initiator(self):
        buff = (ctypes.c_wchar * (iscsi_struct.MAX_ISCSI_NAME_LEN + 1))()
        self._run_and_check_output(iscsidsc.GetIScsiInitiatorNodeNameW,
                                   ctypes.byref(buff))
        return buff.value

    def _login_iscsi_target(self, target_name, portal=None, login_opts=None,
                            is_persistent=True):
        session_id = iscsi_struct.ISCSI_UNIQUE_SESSION_ID()
        connection_id = iscsi_struct.ISCSI_UNIQUE_CONNECTION_ID()
        portal_ref = ctypes.byref(portal) if portal else None
        login_opts_ref = ctypes.byref(login_opts) if login_opts else None

        # If the portal is not provided, the initiator will try to reach any
        # portal exporting the requested target.
        self._run_and_check_output(
            iscsidsc.LoginIScsiTargetW,
            ctypes.c_wchar_p(target_name),
            False,  # IsInformationalSession
            None,  # Initiator name/port (using any available initiator)
            ctypes.c_ulong(iscsi_struct.ISCSI_ANY_INITIATOR_PORT),
            portal_ref,
            iscsi_struct.ISCSI_SECURITY_FLAGS(
                iscsi_struct.ISCSI_DEFAULT_SECURITY_FLAGS),
            None,  # Security flags / mappings (using default / auto)
            login_opts_ref,
            ctypes.c_ulong(0),
            None,  # Preshared key size / key (used for IPsec)
            is_persistent,
            ctypes.byref(session_id),
            ctypes.byref(connection_id))
        return session_id, connection_id

    @ensure_buff_and_retrieve_items(
        struct_type=iscsi_struct.ISCSI_SESSION_INFO)
    def _get_iscsi_sessions(self, buff=None, buff_size=None,
                            element_count=None):
        self._run_and_check_output(
            iscsidsc.GetIScsiSessionListW,
            ctypes.byref(buff_size),
            ctypes.byref(element_count),
            ctypes.byref(buff))

    def _get_iscsi_target_sessions(self, target_name):
        sessions = self._get_iscsi_sessions() or []
        tgt_sessions = [session for session in sessions
                        if session.TargetNodeName == target_name]
        return tgt_sessions

    @ensure_buff_and_retrieve_items(
        struct_type=iscsi_struct.ISCSI_DEVICE_ON_SESSION,
        func_requests_buff_sz=False)
    def _get_iscsi_session_devices(self, session_id,
                                   buff=None, buff_size=None,
                                   element_count=None):
        self._run_and_check_output(
            iscsidsc.GetDevicesForIScsiSessionW,
            ctypes.byref(session_id),
            ctypes.byref(element_count),
            ctypes.byref(buff))

    def _get_iscsi_session_luns(self, session_id):
        devices = self._get_iscsi_session_devices(session_id)
        luns = [device.ScsiAddress.Lun for device in devices]
        return luns

    def get_device_number_for_target(self, target_name, target_lun,
                                     ignore_missing=True):
        sessions = self._get_iscsi_target_sessions(target_name)
        if sessions:
            sid = sessions[0].SessionId
            self._ensure_lun_available(sid, target_name, target_lun)

            devices = self._get_iscsi_session_devices(sid)
            for device in devices:
                if device.ScsiAddress.Lun == target_lun:
                    return device.StorageDeviceNumber.DeviceNumber

        # Note(lpetrut): the Hyper-V driver uses this method in order
        # to check if an iSCSI target is already mounted. Raising
        # an exception here would break other parts of the Hyper-V
        # driver as well.
        LOG.info(_LI('Could not find the device number for lun '
                     '%(target_lun)s on target %(target_iqn)s. '
                     'No session with the iSCSI target exists'),
                 dict(target_iqn=target_name, target_lun=target_lun))

    def get_target_lun_count(self, target_name,
                             disk_type=iscsi_struct.FILE_DEVICE_DISK):
        sessions = self._get_iscsi_target_sessions(target_name)
        lun_count = 0
        if sessions:
            devices = self._get_iscsi_session_devices(sessions[0].SessionId)
            for device in devices:
                if device.StorageDeviceNumber.DeviceType == disk_type:
                    lun_count += 1
        return lun_count

    @ensure_buff_and_retrieve_items(
        struct_type=ctypes.c_ubyte,
        parse_output=False)
    def _send_scsi_report_luns(self, session_id, buff=None,
                               buff_size=None, element_count=None):
        scsi_status = ctypes.c_ubyte(0)
        sense_buff_size = ctypes.c_ulong(iscsi_struct.SENSE_BUFF_SIZE)
        sense_buff = (ctypes.c_ubyte * sense_buff_size.value)()

        self._run_and_check_output(
            iscsidsc.SendScsiReportLuns,
            ctypes.byref(session_id),
            ctypes.byref(scsi_status),
            ctypes.byref(buff_size),
            ctypes.byref(buff),
            ctypes.byref(sense_buff_size),
            ctypes.byref(sense_buff))

    def _logout_iscsi_target(self, session_id):
        self._run_and_check_output(
            iscsidsc.LogoutIScsiTarget,
            ctypes.byref(session_id))

    def _get_login_opts(self, auth_username, auth_password, auth_type):
        # NOTE(lpetrut): if credentials are passed and the authentication
        if auth_type is None:
            auth_type = (constants.ISCSI_CHAP_AUTH_TYPE
                         if auth_username and auth_password
                         else constants.ISCSI_NO_AUTH_TYPE)
        login_opts = iscsi_struct.ISCSI_LOGIN_OPTIONS(Username=auth_username,
                                                      Password=auth_password,
                                                      AuthType=auth_type)
        return login_opts

    def login_storage_target(self, target_lun, target_iqn, target_portal,
                             auth_username=None, auth_password=None,
                             auth_type=None):
        portal_addr, portal_port = _utils.parse_server_string(target_portal)
        login_opts = self._get_login_opts(auth_username,
                                          auth_password,
                                          auth_type)

        portal = iscsi_struct.ISCSI_TARGET_PORTAL(Address=portal_addr,
                                                  Socket=int(portal_port))

        self._update_portal_map(portal.Address,
                                portal.Socket,
                                target_iqn)
        # TODO(lpetrut): handle the case when credentials are requested,
        # as seen in case of some HP backends.
        #
        # Note that this operation is idempotent, we avoid the time required
        # to retrieve the portal list.
        LOG.debug("Ensuring target portal %(target_portal)s is logged in.",
                  dict(target_portal=target_portal))
        self._add_target_portal(portal, login_opts=None)

        # TODO(lpetrut): We should be able to login multiple
        # portals if provided (by adding connections)
        sessions = self._get_iscsi_target_sessions(target_iqn)
        if not sessions:
            discovered_targets = self._get_targets()
            if target_iqn not in discovered_targets:
                self._refresh_target_portal(portal)

            LOG.debug("Logging in iSCSI target %(target_iqn)s",
                      dict(target_iqn=target_iqn))
            # Note(lpetrut): The iscsidsc documentation states that if a
            # persistent session is requested, the initiator should login
            # the target only after saving the credentials.
            #
            # The issue is that although the Microsoft software iSCSI
            # initiator saves the credentials, it does not automatically
            # login the target, for which reason we have two calls, one
            # meant to save the credentials and another one which will
            # create the actual session.
            self._login_iscsi_target(target_iqn, portal, login_opts,
                                     is_persistent=True)
            sid, cid = self._login_iscsi_target(target_iqn, portal,
                                                login_opts,
                                                is_persistent=False)
        else:
            sid = sessions[0].SessionId

        self._ensure_lun_available(sid, target_iqn, target_lun)

    def _ensure_lun_available(self, session_id, target_iqn, target_lun):
        @loopingcall.RetryDecorator(max_retry_count=5, max_sleep_time=3,
                                    exceptions=(
                                        exceptions.ISCSILunNotAvailable, ))
        def wait_for_lun():
            luns = self._get_iscsi_session_luns(session_id)
            if target_lun not in luns:
                self._send_scsi_report_luns(session_id)
                raise exceptions.ISCSILunNotAvailable(target_lun=target_lun,
                                                      target_iqn=target_iqn)
        wait_for_lun()

    def logout_storage_target(self, target_iqn):
        LOG.debug("Logging out iSCSI target %(target_iqn)s",
                  dict(target_iqn=target_iqn))
        sessions = self._get_iscsi_target_sessions(target_iqn)
        for session in sessions:
            sid = session.SessionId
            self._logout_iscsi_target(sid)

        self._remove_target_persistent_logins(target_iqn)

        portals = self._get_portals_exporting_target(target_iqn)
        for portal in portals:
            self._update_portal_map(portal.Address,
                                    portal.Socket,
                                    target_iqn,
                                    remove=True)
            if not self._portal_in_use(portal.Address, portal.Socket):
                LOG.debug("Logging out iSCSI portal %(addr)s:%(port)s",
                          dict(addr=portal.Address,
                               port=portal.Socket))
                self._remove_target_portal(portal)

    def _remove_target_persistent_logins(self, target_iqn):
        persistent_logins = self._get_iscsi_persistent_logins()
        for persistent_login in persistent_logins:
            if persistent_login.TargetName == target_iqn:
                LOG.debug("Removing iSCSI target "
                          "persistent login: %(target_iqn)s",
                          dict(target_iqn=target_iqn))
                self._remove_persistent_login(persistent_login)

    def _remove_persistent_login(self, persistent_login):
        self._run_and_check_output(
            iscsidsc.RemoveIScsiPersistentTargetW,
            ctypes.c_wchar_p(persistent_login.InitiatorInstance),
            persistent_login.InitiatorPortNumber,
            ctypes.c_wchar_p(persistent_login.TargetName),
            ctypes.byref(persistent_login.TargetPortal))
