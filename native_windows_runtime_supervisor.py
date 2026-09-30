"""Native Windows AppContainer backend for supervised one-shot workers."""

import ctypes
from ctypes import wintypes
import hashlib
import json
import os
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path

from runtime_supervisor import StopResult


_GENERATION_ID = re.compile(r"[0-9a-f]{32}\Z")
_PROJECT = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}\Z")
_RUNTIME_NAME = re.compile(r"[a-z0-9][a-z0-9_.-]{0,31}\Z")

LPVOID = ctypes.c_void_p
SIZE_T = ctypes.c_size_t
ULONG_PTR = ctypes.c_size_t


class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("nLength", wintypes.DWORD),
        ("lpSecurityDescriptor", LPVOID),
        ("bInheritHandle", wintypes.BOOL),
    ]


class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Sid", LPVOID), ("Attributes", wintypes.DWORD)]


class SECURITY_CAPABILITIES(ctypes.Structure):
    _fields_ = [
        ("AppContainerSid", LPVOID),
        ("Capabilities", ctypes.POINTER(SID_AND_ATTRIBUTES)),
        ("CapabilityCount", wintypes.DWORD),
        ("Reserved", wintypes.DWORD),
    ]


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(ctypes.c_ubyte)),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class STARTUPINFOEXW(ctypes.Structure):
    _fields_ = [
        ("StartupInfo", STARTUPINFOW),
        ("lpAttributeList", LPVOID),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_longlong),
        ("PerJobUserTimeLimit", ctypes.c_longlong),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", SIZE_T),
        ("MaximumWorkingSetSize", SIZE_T),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ULONG_PTR),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class IO_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_ulonglong),
        ("WriteOperationCount", ctypes.c_ulonglong),
        ("OtherOperationCount", ctypes.c_ulonglong),
        ("ReadTransferCount", ctypes.c_ulonglong),
        ("WriteTransferCount", ctypes.c_ulonglong),
        ("OtherTransferCount", ctypes.c_ulonglong),
    ]


class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", IO_COUNTERS),
        ("ProcessMemoryLimit", SIZE_T),
        ("JobMemoryLimit", SIZE_T),
        ("PeakProcessMemoryUsed", SIZE_T),
        ("PeakJobMemoryUsed", SIZE_T),
    ]


class _WindowsAPI:
    ERROR_ALREADY_EXISTS = 183
    ERROR_BROKEN_PIPE = 109
    ERROR_INSUFFICIENT_BUFFER = 122
    STILL_ACTIVE = 259
    WAIT_OBJECT_0 = 0
    WAIT_TIMEOUT = 258
    INFINITE = 0xFFFFFFFF
    HANDLE_FLAG_INHERIT = 0x1
    STARTF_USESTDHANDLES = 0x100
    CREATE_SUSPENDED = 0x4
    CREATE_NO_WINDOW = 0x08000000
    EXTENDED_STARTUPINFO_PRESENT = 0x00080000
    CREATE_UNICODE_ENVIRONMENT = 0x00000400
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002
    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009
    TOKEN_QUERY = 0x0008
    PROCESS_TERMINATE = 0x0001
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    SYNCHRONIZE = 0x00100000
    JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
    JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
    JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x00000400
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
    JOB_OBJECT_TERMINATE = 0x0008
    JOB_OBJECT_QUERY = 0x0004
    JobObjectExtendedLimitInformation = 9
    TokenIntegrityLevel = 25
    TokenIsAppContainer = 29
    TokenCapabilities = 30

    def __init__(self):
        if os.name != "nt":
            raise RuntimeError("native Windows supervisor requires Windows")
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        self.userenv = ctypes.WinDLL("userenv", use_last_error=True)
        self.ole32 = ctypes.WinDLL("ole32", use_last_error=True)
        self._declare()

    def _declare(self):
        k32 = self.kernel32
        adv = self.advapi32
        user = self.userenv
        k32.CloseHandle.argtypes = [wintypes.HANDLE]
        k32.CloseHandle.restype = wintypes.BOOL
        k32.LocalFree.argtypes = [LPVOID]
        k32.LocalFree.restype = LPVOID
        k32.GetCurrentProcess.restype = wintypes.HANDLE
        k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        k32.OpenProcess.restype = wintypes.HANDLE
        k32.GetProcessTimes.argtypes = [
            wintypes.HANDLE, ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME), ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
        ]
        k32.GetProcessTimes.restype = wintypes.BOOL
        k32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        k32.GetExitCodeProcess.restype = wintypes.BOOL
        k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        k32.WaitForSingleObject.restype = wintypes.DWORD
        k32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
        k32.TerminateProcess.restype = wintypes.BOOL
        k32.CreatePipe.argtypes = [
            ctypes.POINTER(wintypes.HANDLE), ctypes.POINTER(wintypes.HANDLE),
            ctypes.POINTER(SECURITY_ATTRIBUTES), wintypes.DWORD,
        ]
        k32.CreatePipe.restype = wintypes.BOOL
        k32.SetHandleInformation.argtypes = [
            wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD,
        ]
        k32.SetHandleInformation.restype = wintypes.BOOL
        k32.ReadFile.argtypes = [
            wintypes.HANDLE, LPVOID, wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD), LPVOID,
        ]
        k32.ReadFile.restype = wintypes.BOOL
        k32.WriteFile.argtypes = [
            wintypes.HANDLE, LPVOID, wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD), LPVOID,
        ]
        k32.WriteFile.restype = wintypes.BOOL
        k32.InitializeProcThreadAttributeList.argtypes = [
            LPVOID, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(SIZE_T),
        ]
        k32.InitializeProcThreadAttributeList.restype = wintypes.BOOL
        k32.UpdateProcThreadAttribute.argtypes = [
            LPVOID, wintypes.DWORD, SIZE_T, LPVOID, SIZE_T, LPVOID,
            ctypes.POINTER(SIZE_T),
        ]
        k32.UpdateProcThreadAttribute.restype = wintypes.BOOL
        k32.DeleteProcThreadAttributeList.argtypes = [LPVOID]
        k32.CreateJobObjectW.argtypes = [LPVOID, wintypes.LPCWSTR]
        k32.CreateJobObjectW.restype = wintypes.HANDLE
        k32.OpenJobObjectW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
        k32.OpenJobObjectW.restype = wintypes.HANDLE
        k32.SetInformationJobObject.argtypes = [
            wintypes.HANDLE, ctypes.c_int, LPVOID, wintypes.DWORD,
        ]
        k32.SetInformationJobObject.restype = wintypes.BOOL
        k32.QueryInformationJobObject.argtypes = [
            wintypes.HANDLE, ctypes.c_int, LPVOID, wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        k32.QueryInformationJobObject.restype = wintypes.BOOL
        k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        k32.AssignProcessToJobObject.restype = wintypes.BOOL
        k32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        k32.TerminateJobObject.restype = wintypes.BOOL
        k32.ResumeThread.argtypes = [wintypes.HANDLE]
        k32.ResumeThread.restype = wintypes.DWORD
        adv.OpenProcessToken.argtypes = [
            wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE),
        ]
        adv.OpenProcessToken.restype = wintypes.BOOL
        adv.CreateProcessAsUserW.argtypes = [
            wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPWSTR, LPVOID, LPVOID,
            wintypes.BOOL, wintypes.DWORD, LPVOID, wintypes.LPCWSTR,
            ctypes.POINTER(STARTUPINFOW), ctypes.POINTER(PROCESS_INFORMATION),
        ]
        adv.CreateProcessAsUserW.restype = wintypes.BOOL
        adv.ConvertSidToStringSidW.argtypes = [LPVOID, ctypes.POINTER(wintypes.LPWSTR)]
        adv.ConvertSidToStringSidW.restype = wintypes.BOOL
        adv.GetTokenInformation.argtypes = [
            wintypes.HANDLE, ctypes.c_int, LPVOID, wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        adv.GetTokenInformation.restype = wintypes.BOOL
        adv.GetSidSubAuthorityCount.argtypes = [LPVOID]
        adv.GetSidSubAuthorityCount.restype = ctypes.POINTER(ctypes.c_ubyte)
        adv.GetSidSubAuthority.argtypes = [LPVOID, wintypes.DWORD]
        adv.GetSidSubAuthority.restype = ctypes.POINTER(wintypes.DWORD)
        adv.FreeSid.argtypes = [LPVOID]
        adv.FreeSid.restype = LPVOID
        self.ole32.CoTaskMemFree.argtypes = [LPVOID]
        self.ole32.CoTaskMemFree.restype = None
        user.CreateAppContainerProfile.argtypes = [
            wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR,
            ctypes.POINTER(SID_AND_ATTRIBUTES), wintypes.DWORD,
            ctypes.POINTER(LPVOID),
        ]
        user.CreateAppContainerProfile.restype = ctypes.c_long
        user.DeriveAppContainerSidFromAppContainerName.argtypes = [
            wintypes.LPCWSTR, ctypes.POINTER(LPVOID),
        ]
        user.DeriveAppContainerSidFromAppContainerName.restype = ctypes.c_long
        user.DeleteAppContainerProfile.argtypes = [wintypes.LPCWSTR]
        user.DeleteAppContainerProfile.restype = ctypes.c_long
        user.GetAppContainerFolderPath.argtypes = [
            wintypes.LPCWSTR, ctypes.POINTER(wintypes.LPWSTR),
        ]
        user.GetAppContainerFolderPath.restype = ctypes.c_long

    @staticmethod
    def _hresult_code(result: int) -> int:
        return result & 0xFFFFFFFF

    @staticmethod
    def _win_error(operation: str) -> OSError:
        return ctypes.WinError(ctypes.get_last_error(), operation)

    def close(self, handle) -> None:
        if handle:
            self.kernel32.CloseHandle(handle)

    def create_profile(self, name: str) -> tuple[LPVOID, str, Path]:
        sid = LPVOID()
        result = self.userenv.CreateAppContainerProfile(
            name, name, "Governance Substrate isolated worker", None, 0,
            ctypes.byref(sid),
        )
        if self._hresult_code(result) == 0x800700B7:
            result = self.userenv.DeriveAppContainerSidFromAppContainerName(
                name, ctypes.byref(sid)
            )
        if result != 0 or not sid:
            raise OSError(self._hresult_code(result), "create AppContainer profile")
        sid_text_pointer = wintypes.LPWSTR()
        if not self.advapi32.ConvertSidToStringSidW(
                sid, ctypes.byref(sid_text_pointer)):
            self.advapi32.FreeSid(sid)
            raise self._win_error("convert AppContainer SID")
        try:
            sid_text = sid_text_pointer.value
        finally:
            self.kernel32.LocalFree(sid_text_pointer)
        folder_pointer = wintypes.LPWSTR()
        result = self.userenv.GetAppContainerFolderPath(
            sid_text, ctypes.byref(folder_pointer)
        )
        if result != 0:
            self.advapi32.FreeSid(sid)
            raise OSError(self._hresult_code(result), "get AppContainer folder")
        try:
            folder = Path(folder_pointer.value).resolve(strict=True)
        finally:
            self.ole32.CoTaskMemFree(folder_pointer)
        return sid, sid_text, folder

    def delete_profile(self, name: str) -> None:
        result = self.userenv.DeleteAppContainerProfile(name)
        code = self._hresult_code(result)
        if code not in (0, 0x80070002):
            raise OSError(code, "delete AppContainer profile")


class _WindowsWorkerProcess:
    def __init__(self, api: _WindowsAPI, info: PROCESS_INFORMATION,
                 job, stdin_write, stdout_read, stderr_read):
        self.api = api
        self.pid = int(info.dwProcessId)
        self.process_handle = info.hProcess
        self.job_handle = job
        self.stdin_write = stdin_write
        self.stdout_read = stdout_read
        self.stderr_read = stderr_read
        self.returncode = None
        self._lock = threading.RLock()

    def _read_all(self, handle, destination: list[bytes]) -> None:
        while True:
            buffer = ctypes.create_string_buffer(4096)
            count = wintypes.DWORD()
            if not self.api.kernel32.ReadFile(
                    handle, buffer, len(buffer), ctypes.byref(count), None):
                if ctypes.get_last_error() == self.api.ERROR_BROKEN_PIPE:
                    return
                return
            if count.value == 0:
                return
            destination.append(buffer.raw[:count.value])

    def _write_all(self, payload: bytes) -> None:
        offset = 0
        while offset < len(payload):
            count = wintypes.DWORD()
            chunk = payload[offset:offset + 65536]
            buffer = ctypes.create_string_buffer(chunk)
            if not self.api.kernel32.WriteFile(
                    self.stdin_write, buffer, len(chunk), ctypes.byref(count), None):
                raise self.api._win_error("write sealed worker input")
            offset += count.value

    def communicate(self, input: str, timeout: float) -> tuple[str, str]:
        stdout_parts: list[bytes] = []
        stderr_parts: list[bytes] = []
        stdout_thread = threading.Thread(
            target=self._read_all, args=(self.stdout_read, stdout_parts), daemon=True
        )
        stderr_thread = threading.Thread(
            target=self._read_all, args=(self.stderr_read, stderr_parts), daemon=True
        )
        stdout_thread.start()
        stderr_thread.start()
        self._write_all(input.encode("utf-8"))
        self.api.close(self.stdin_write)
        self.stdin_write = None
        result = self.api.kernel32.WaitForSingleObject(
            self.process_handle, max(1, int(timeout * 1000))
        )
        if result == self.api.WAIT_TIMEOUT:
            raise subprocess.TimeoutExpired("native Windows worker", timeout)
        if result != self.api.WAIT_OBJECT_0:
            raise self.api._win_error("wait for native Windows worker")
        exit_code = wintypes.DWORD()
        if not self.api.kernel32.GetExitCodeProcess(
                self.process_handle, ctypes.byref(exit_code)):
            raise self.api._win_error("read native Windows worker exit code")
        self.returncode = int(exit_code.value)
        stdout_thread.join(timeout=5)
        stderr_thread.join(timeout=5)
        return (
            b"".join(stdout_parts).decode("utf-8", errors="replace"),
            b"".join(stderr_parts).decode("utf-8", errors="replace"),
        )

    def poll(self):
        if self.returncode is not None:
            return self.returncode
        result = self.api.kernel32.WaitForSingleObject(self.process_handle, 0)
        if result == self.api.WAIT_TIMEOUT:
            return None
        if result != self.api.WAIT_OBJECT_0:
            return None
        exit_code = wintypes.DWORD()
        if self.api.kernel32.GetExitCodeProcess(
                self.process_handle, ctypes.byref(exit_code)):
            self.returncode = int(exit_code.value)
        return self.returncode

    def wait(self, timeout: float = 5.0):
        result = self.api.kernel32.WaitForSingleObject(
            self.process_handle, max(1, int(timeout * 1000))
        )
        if result == self.api.WAIT_TIMEOUT:
            raise subprocess.TimeoutExpired("native Windows worker", timeout)
        return self.poll()

    def terminate_job(self) -> bool:
        if not self.job_handle:
            return False
        return bool(self.api.kernel32.TerminateJobObject(self.job_handle, 1))

    def close_job(self) -> None:
        with self._lock:
            if self.job_handle:
                self.api.close(self.job_handle)
                self.job_handle = None

    def close(self) -> None:
        with self._lock:
            for name in (
                "stdin_write", "stdout_read", "stderr_read", "process_handle",
                "job_handle",
            ):
                handle = getattr(self, name)
                if handle:
                    self.api.close(handle)
                    setattr(self, name, None)


class NativeWindowsRuntimeSupervisor:
    """Run one zero-capability AppContainer process per generation."""

    def __init__(self, worker: str | Path, state_dir: str | Path, project: str,
                 runtime_name: str = "native-windows"):
        self.api = _WindowsAPI()
        self.worker = Path(worker).resolve(strict=True)
        if not self.worker.is_file() or self.worker.suffix.lower() != ".exe":
            raise ValueError("native Windows worker must be an executable")
        if not isinstance(project, str) or not _PROJECT.fullmatch(project):
            raise ValueError("unique lowercase runtime project required")
        if (not isinstance(runtime_name, str) or
                not _RUNTIME_NAME.fullmatch(runtime_name)):
            raise ValueError("valid lowercase runtime name required")
        self.project = project
        self.runtime_name = runtime_name
        self.worker_sha256 = hashlib.sha256(self.worker.read_bytes()).hexdigest()
        self.state_dir = Path(state_dir).resolve() / project
        self.worker_dir = self.state_dir / "workers"
        self.worker_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._running: dict[str, _WindowsWorkerProcess] = {}
        self._cancelled: set[str] = set()
        self._started: set[str] = set()

    @staticmethod
    def _validate_generation(generation_id: str) -> None:
        if not isinstance(generation_id, str) or not _GENERATION_ID.fullmatch(generation_id):
            raise ValueError("invalid generation ID")

    def _profile_name(self, generation_id: str) -> str:
        self._validate_generation(generation_id)
        project_hash = hashlib.sha256(self.project.encode()).hexdigest()[:12]
        return f"GovSubstrate.{project_hash}.{generation_id}"

    def _job_name(self, generation_id: str) -> str:
        self._validate_generation(generation_id)
        project_hash = hashlib.sha256(self.project.encode()).hexdigest()[:12]
        return f"Local\\GovSubstrate-{project_hash}-{generation_id}"

    def _record_path(self, generation_id: str) -> Path:
        self._validate_generation(generation_id)
        return self.worker_dir / f"{generation_id}.json"

    @staticmethod
    def _process_birth_from_handle(api: _WindowsAPI, handle) -> str | None:
        exit_code = wintypes.DWORD()
        if (not api.kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)) or
                exit_code.value != api.STILL_ACTIVE):
            return None
        creation = wintypes.FILETIME()
        exit_time = wintypes.FILETIME()
        kernel = wintypes.FILETIME()
        user = wintypes.FILETIME()
        if not api.kernel32.GetProcessTimes(
                handle, ctypes.byref(creation), ctypes.byref(exit_time),
                ctypes.byref(kernel), ctypes.byref(user)):
            return None
        return str((creation.dwHighDateTime << 32) | creation.dwLowDateTime)

    def _process_birth(self, pid: int) -> str | None:
        handle = self.api.kernel32.OpenProcess(
            self.api.PROCESS_QUERY_LIMITED_INFORMATION | self.api.SYNCHRONIZE,
            False, pid,
        )
        if not handle:
            return None
        try:
            return self._process_birth_from_handle(self.api, handle)
        finally:
            self.api.close(handle)

    def _write_record(self, generation_id: str, pid: int, birth: str,
                      profile_name: str, profile_sid: str, job_name: str) -> str:
        runtime_id = f"{pid}:{birth}"
        record = {
            "schema": 1,
            "project": self.project,
            "generation_id": generation_id,
            "pid": pid,
            "birth": birth,
            "runtime_id": runtime_id,
            "worker_sha256": self.worker_sha256,
            "profile_name": profile_name,
            "profile_sid": profile_sid,
            "job_name": job_name,
        }
        destination = self._record_path(generation_id)
        temporary = destination.with_suffix(".tmp")
        temporary.write_text(json.dumps(record, sort_keys=True) + "\n",
                             encoding="utf-8")
        os.replace(temporary, destination)
        return runtime_id

    def _read_record(self, generation_id: str) -> dict | None:
        path = self._record_path(generation_id)
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        expected = {
            "schema", "project", "generation_id", "pid", "birth",
            "runtime_id", "worker_sha256", "profile_name", "profile_sid",
            "job_name",
        }
        if (type(record) is not dict or set(record) != expected or
                record["schema"] != 1 or record["project"] != self.project or
                record["generation_id"] != generation_id or
                type(record["pid"]) is not int or record["pid"] <= 0 or
                type(record["birth"]) is not str or not record["birth"] or
                record["runtime_id"] != f"{record['pid']}:{record['birth']}" or
                record["worker_sha256"] != self.worker_sha256 or
                record["profile_name"] != self._profile_name(generation_id) or
                record["job_name"] != self._job_name(generation_id) or
                not re.fullmatch(r"S-1-15-2(?:-\d+)+", record["profile_sid"])):
            raise RuntimeError("native Windows worker identity mismatch")
        return record

    def _record_running(self, record: dict) -> bool:
        return self._process_birth(record["pid"]) == record["birth"]

    def runtime_exists(self, runtime_id: str) -> bool:
        try:
            pid_text, birth = runtime_id.split(":", 1)
            pid = int(pid_text)
        except (AttributeError, ValueError):
            return False
        return self._process_birth(pid) == birth

    def runtime_identity(self, generation_id: str) -> str | None:
        with self._lock:
            record = self._read_record(generation_id)
            if record is None or not self._record_running(record):
                return None
            return record["runtime_id"]

    def _create_pipe(self) -> tuple[wintypes.HANDLE, wintypes.HANDLE]:
        security = SECURITY_ATTRIBUTES(
            ctypes.sizeof(SECURITY_ATTRIBUTES), None, True
        )
        read_handle = wintypes.HANDLE()
        write_handle = wintypes.HANDLE()
        if not self.api.kernel32.CreatePipe(
                ctypes.byref(read_handle), ctypes.byref(write_handle),
                ctypes.byref(security), 0):
            raise self.api._win_error("create worker pipe")
        return read_handle, write_handle

    def _prepare_profile(self, generation_id: str):
        profile_name = self._profile_name(generation_id)
        sid, sid_text, profile_root = self.api.create_profile(profile_name)
        try:
            run_root = profile_root / "LocalState" / "run"
            private_tmp = run_root / "tmp"
            private_shm = run_root / "shm"
            private_tmp.mkdir(parents=True, exist_ok=False)
            private_shm.mkdir()
            copied_worker = run_root / "gov-runtime-probe.exe"
            shutil.copyfile(self.worker, copied_worker)
            if hashlib.sha256(copied_worker.read_bytes()).hexdigest() != self.worker_sha256:
                raise RuntimeError("native Windows worker copy verification failed")
            icacls = (
                Path(os.environ.get("SystemRoot", r"C:\Windows")) /
                "System32" / "icacls.exe"
            )
            result = subprocess.run(
                [str(icacls), str(run_root), "/grant",
                 f"*{sid_text}:(OI)(CI)F", "/T", "/C"],
                capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=30,
            )
            if result.returncode:
                raise RuntimeError("explicit AppContainer ACL grant failed")
            return (
                profile_name, sid, sid_text, run_root, private_tmp,
                private_shm, copied_worker,
            )
        except Exception:
            self.api.advapi32.FreeSid(sid)
            try:
                self.api.delete_profile(profile_name)
            except OSError:
                pass
            raise

    def _spawn(self, generation_id: str) -> tuple[_WindowsWorkerProcess, str]:
        with self._lock:
            self._validate_generation(generation_id)
            if generation_id in self._started or generation_id in self._cancelled:
                raise RuntimeError("generation already running or revoked")
            self._started.add(generation_id)
            profile_name = None
            sid = None
            handles = []
            process = None
            attribute_buffer = None
            attribute_list = None
            info = PROCESS_INFORMATION()
            try:
                (profile_name, sid, sid_text, run_root, private_tmp,
                 private_shm, copied_worker) = self._prepare_profile(generation_id)
                stdin_read, stdin_write = self._create_pipe()
                stdout_read, stdout_write = self._create_pipe()
                stderr_read, stderr_write = self._create_pipe()
                handles.extend([
                    stdin_read, stdin_write, stdout_read, stdout_write,
                    stderr_read, stderr_write,
                ])
                for parent_handle in (stdin_write, stdout_read, stderr_read):
                    if not self.api.kernel32.SetHandleInformation(
                            parent_handle, self.api.HANDLE_FLAG_INHERIT, 0):
                        raise self.api._win_error("limit inherited pipe handles")

                attribute_size = SIZE_T()
                self.api.kernel32.InitializeProcThreadAttributeList(
                    None, 2, 0, ctypes.byref(attribute_size)
                )
                if ctypes.get_last_error() != self.api.ERROR_INSUFFICIENT_BUFFER:
                    raise self.api._win_error("size process attribute list")
                attribute_buffer = ctypes.create_string_buffer(attribute_size.value)
                attribute_list = ctypes.cast(attribute_buffer, LPVOID)
                if not self.api.kernel32.InitializeProcThreadAttributeList(
                        attribute_list, 2, 0, ctypes.byref(attribute_size)):
                    raise self.api._win_error("initialize process attribute list")
                capabilities = SECURITY_CAPABILITIES(
                    sid, None, 0, 0
                )
                if not self.api.kernel32.UpdateProcThreadAttribute(
                        attribute_list, 0,
                        self.api.PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                        ctypes.byref(capabilities), ctypes.sizeof(capabilities),
                        None, None):
                    raise self.api._win_error("set AppContainer process attribute")
                inherited = (wintypes.HANDLE * 3)(
                    stdin_read, stdout_write, stderr_write
                )
                if not self.api.kernel32.UpdateProcThreadAttribute(
                        attribute_list, 0,
                        self.api.PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                        inherited, ctypes.sizeof(inherited), None, None):
                    raise self.api._win_error("set inherited handle allowlist")

                startup = STARTUPINFOEXW()
                startup.StartupInfo.cb = ctypes.sizeof(startup)
                startup.StartupInfo.dwFlags = self.api.STARTF_USESTDHANDLES
                startup.StartupInfo.hStdInput = stdin_read
                startup.StartupInfo.hStdOutput = stdout_write
                startup.StartupInfo.hStdError = stderr_write
                startup.lpAttributeList = attribute_list
                command_line = ctypes.create_unicode_buffer(
                    subprocess.list2cmdline([str(copied_worker)])
                )
                system_root = os.environ.get("SystemRoot", r"C:\Windows")
                system_drive = Path(system_root).drive
                safe_environment = {
                    "ComSpec": str(Path(system_root) / "System32" / "cmd.exe"),
                    "GOV_PRIVATE_SHM": str(private_shm),
                    "LOCALAPPDATA": str(run_root),
                    "Path": str(Path(system_root) / "System32") + ";" + system_root,
                    "SystemDrive": system_drive,
                    "SystemRoot": system_root,
                    "TEMP": str(private_tmp),
                    "TMP": str(private_tmp),
                    "USERPROFILE": str(run_root),
                    "windir": system_root,
                }
                environment_text = "\0".join(
                    f"{name}={value}" for name, value in sorted(
                        safe_environment.items(), key=lambda item: item[0].casefold()
                    )
                ) + "\0\0"
                environment = ctypes.create_unicode_buffer(environment_text)
                flags = (
                    self.api.CREATE_SUSPENDED | self.api.CREATE_NO_WINDOW |
                    self.api.EXTENDED_STARTUPINFO_PRESENT |
                    self.api.CREATE_UNICODE_ENVIRONMENT
                )
                if not self.api.advapi32.CreateProcessAsUserW(
                        None, str(copied_worker), command_line,
                        None, None, True, flags, environment, str(run_root),
                        ctypes.cast(ctypes.byref(startup),
                                    ctypes.POINTER(STARTUPINFOW)),
                        ctypes.byref(info)):
                    raise self.api._win_error("create AppContainer worker")

                job_name = self._job_name(generation_id)
                job = self.api.kernel32.CreateJobObjectW(None, job_name)
                if not job:
                    raise self.api._win_error("create worker Job Object")
                handles.append(job)
                limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
                limits.BasicLimitInformation.LimitFlags = (
                    self.api.JOB_OBJECT_LIMIT_ACTIVE_PROCESS |
                    self.api.JOB_OBJECT_LIMIT_PROCESS_MEMORY |
                    self.api.JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION |
                    self.api.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                )
                limits.BasicLimitInformation.ActiveProcessLimit = 1
                limits.ProcessMemoryLimit = 134217728
                if not self.api.kernel32.SetInformationJobObject(
                        job, self.api.JobObjectExtendedLimitInformation,
                        ctypes.byref(limits), ctypes.sizeof(limits)):
                    raise self.api._win_error("configure worker Job Object")
                if not self.api.kernel32.AssignProcessToJobObject(job, info.hProcess):
                    raise self.api._win_error("assign AppContainer to Job Object")
                birth = self._process_birth_from_handle(self.api, info.hProcess)
                if birth is None:
                    raise RuntimeError("native Windows process identity unavailable")
                runtime_id = self._write_record(
                    generation_id, int(info.dwProcessId), birth, profile_name,
                    sid_text, job_name,
                )
                if self.api.kernel32.ResumeThread(info.hThread) == 0xFFFFFFFF:
                    raise self.api._win_error("resume AppContainer worker")
                self.api.close(info.hThread)
                info.hThread = None
                for child_handle in (stdin_read, stdout_write, stderr_write):
                    self.api.close(child_handle)
                    handles.remove(child_handle)
                process = _WindowsWorkerProcess(
                    self.api, info, job, stdin_write, stdout_read, stderr_read
                )
                for owned in (job, stdin_write, stdout_read, stderr_read):
                    handles.remove(owned)
                info.hProcess = None
                self._running[generation_id] = process
                return process, runtime_id
            except Exception:
                if info.hProcess:
                    self.api.kernel32.TerminateProcess(info.hProcess, 1)
                    self.api.kernel32.WaitForSingleObject(info.hProcess, 5000)
                self._record_path(generation_id).unlink(missing_ok=True)
                if profile_name:
                    try:
                        self.api.delete_profile(profile_name)
                    except OSError:
                        pass
                raise
            finally:
                if attribute_list:
                    self.api.kernel32.DeleteProcThreadAttributeList(attribute_list)
                if sid:
                    self.api.advapi32.FreeSid(sid)
                self.api.close(info.hThread)
                self.api.close(info.hProcess)
                for handle in handles:
                    self.api.close(handle)

    def run(self, generation_id: str, sealed_context: str) -> str:
        process, _ = self._spawn(generation_id)
        try:
            try:
                stdout, stderr = process.communicate(sealed_context, timeout=130)
            except subprocess.TimeoutExpired:
                self.stop((generation_id,))
                raise RuntimeError("local generation timed out") from None
            with self._lock:
                if generation_id in self._cancelled or process.returncode:
                    self.stop((generation_id,))
                    detail = stderr.strip()
                    message = "local generation stopped or failed"
                    if detail and generation_id not in self._cancelled:
                        message += f": {detail}"
                    raise RuntimeError(message)
                record = self._read_record(generation_id)
                if record is None or self._record_running(record):
                    self.stop((generation_id,))
                    raise RuntimeError("local worker exit could not be verified")
                self._remove_state(generation_id, record)
                return stdout
        finally:
            process.close()
            with self._lock:
                self._running.pop(generation_id, None)

    def _remove_state(self, generation_id: str, record: dict | None = None) -> None:
        if record is None:
            record = self._read_record(generation_id)
        self._record_path(generation_id).unlink(missing_ok=True)
        if record is not None:
            self.api.delete_profile(record["profile_name"])

    def _wait_gone(self, record: dict, timeout: float = 5.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not self._record_running(record):
                return True
            time.sleep(0.05)
        return not self._record_running(record)

    def _terminate(self, record: dict, process: _WindowsWorkerProcess | None) -> bool:
        if not self._record_running(record):
            return True
        terminated = False
        if process is not None:
            terminated = process.terminate_job()
        if not terminated:
            job = self.api.kernel32.OpenJobObjectW(
                self.api.JOB_OBJECT_TERMINATE | self.api.JOB_OBJECT_QUERY,
                False, record["job_name"],
            )
            if job:
                try:
                    terminated = bool(
                        self.api.kernel32.TerminateJobObject(job, 1)
                    )
                finally:
                    self.api.close(job)
        if not terminated:
            handle = self.api.kernel32.OpenProcess(
                self.api.PROCESS_TERMINATE | self.api.SYNCHRONIZE |
                self.api.PROCESS_QUERY_LIMITED_INFORMATION,
                False, record["pid"],
            )
            if handle:
                try:
                    if self._process_birth_from_handle(self.api, handle) == record["birth"]:
                        terminated = bool(
                            self.api.kernel32.TerminateProcess(handle, 1)
                        )
                finally:
                    self.api.close(handle)
        return terminated and self._wait_gone(record)

    def stop(self, generation_ids: tuple[str, ...]) -> tuple[StopResult, ...]:
        with self._lock:
            return tuple(self._stop_one(generation_id) for generation_id in generation_ids)

    def _stop_one(self, generation_id: str) -> StopResult:
        self._validate_generation(generation_id)
        self._cancelled.add(generation_id)
        process = self._running.get(generation_id)
        runtime_id = None
        try:
            record = self._read_record(generation_id)
            if record is None:
                return StopResult(
                    generation_id, self.runtime_name, None, True, "absent"
                )
            runtime_id = record["runtime_id"]
            was_running = self._record_running(record)
            if was_running and not self._terminate(record, process):
                raise RuntimeError("worker exit unverified")
            if process is not None:
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    raise RuntimeError("worker exit unverified") from None
                process.close_job()
            self._remove_state(generation_id, record)
            return StopResult(
                generation_id, self.runtime_name, runtime_id, True,
                "stopped" if was_running else "absent",
            )
        except (OSError, ValueError, RuntimeError, json.JSONDecodeError):
            return StopResult(
                generation_id, self.runtime_name, runtime_id, False,
                "stop_unconfirmed",
            )

    def reconcile(self) -> tuple[StopResult, ...]:
        generations = []
        for path in sorted(self.worker_dir.glob("*.json")):
            generation_id = path.stem
            self._validate_generation(generation_id)
            self._read_record(generation_id)
            generations.append(generation_id)
        return self.stop(tuple(generations))

    def security_state(self, generation_id: str) -> dict:
        record = self._read_record(generation_id)
        if record is None or not self._record_running(record):
            raise RuntimeError("native Windows worker is not running")
        process_handle = self.api.kernel32.OpenProcess(
            self.api.PROCESS_QUERY_LIMITED_INFORMATION,
            False, record["pid"],
        )
        if not process_handle:
            raise self.api._win_error("open native Windows worker")
        token = wintypes.HANDLE()
        job = None
        try:
            if not self.api.advapi32.OpenProcessToken(
                    process_handle, self.api.TOKEN_QUERY, ctypes.byref(token)):
                raise self.api._win_error("open native Windows worker token")
            appcontainer = wintypes.DWORD()
            returned = wintypes.DWORD()
            if not self.api.advapi32.GetTokenInformation(
                    token, self.api.TokenIsAppContainer,
                    ctypes.byref(appcontainer), ctypes.sizeof(appcontainer),
                    ctypes.byref(returned)):
                raise self.api._win_error("query AppContainer token")
            capability_size = wintypes.DWORD()
            self.api.advapi32.GetTokenInformation(
                token, self.api.TokenCapabilities, None, 0,
                ctypes.byref(capability_size),
            )
            if not capability_size.value:
                raise self.api._win_error("size capability token query")
            capability_buffer = ctypes.create_string_buffer(capability_size.value)
            if not self.api.advapi32.GetTokenInformation(
                    token, self.api.TokenCapabilities, capability_buffer,
                    capability_size, ctypes.byref(capability_size)):
                raise self.api._win_error("query capability token")
            capability_count = ctypes.cast(
                capability_buffer, ctypes.POINTER(wintypes.DWORD)
            ).contents.value
            size = wintypes.DWORD()
            self.api.advapi32.GetTokenInformation(
                token, self.api.TokenIntegrityLevel, None, 0, ctypes.byref(size)
            )
            if ctypes.get_last_error() != self.api.ERROR_INSUFFICIENT_BUFFER:
                raise self.api._win_error("size integrity token query")
            buffer = ctypes.create_string_buffer(size.value)
            if not self.api.advapi32.GetTokenInformation(
                    token, self.api.TokenIntegrityLevel, buffer, size,
                    ctypes.byref(size)):
                raise self.api._win_error("query integrity token")
            sid = ctypes.cast(buffer, ctypes.POINTER(SID_AND_ATTRIBUTES)).contents.Sid
            count = self.api.advapi32.GetSidSubAuthorityCount(sid).contents.value
            integrity = self.api.advapi32.GetSidSubAuthority(sid, count - 1).contents.value
            job = self.api.kernel32.OpenJobObjectW(
                self.api.JOB_OBJECT_QUERY, False, record["job_name"]
            )
            if not job:
                raise self.api._win_error("open native Windows Job Object")
            limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
            if not self.api.kernel32.QueryInformationJobObject(
                    job, self.api.JobObjectExtendedLimitInformation,
                    ctypes.byref(limits), ctypes.sizeof(limits), None):
                raise self.api._win_error("query native Windows Job Object")
            flags = limits.BasicLimitInformation.LimitFlags
            required = (
                self.api.JOB_OBJECT_LIMIT_ACTIVE_PROCESS |
                self.api.JOB_OBJECT_LIMIT_PROCESS_MEMORY |
                self.api.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            )
            return {
                "appcontainer": bool(appcontainer.value),
                "capability_count": capability_count,
                "integrity_rid": integrity,
                "job_limit_flags": flags,
                "job_required_limits": (flags & required) == required,
                "active_process_limit": limits.BasicLimitInformation.ActiveProcessLimit,
                "process_memory_limit": int(limits.ProcessMemoryLimit),
            }
        finally:
            self.api.close(job)
            self.api.close(token)
            self.api.close(process_handle)
