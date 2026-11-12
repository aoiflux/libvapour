package tokenprivileges

type documentedPrivilege struct {
	constant  string
	privilege string
	userRight string
}

// LUIDs from [MS-LSAD] 3.1.1.2.1; 36 from the kernel's SeExports (S45 M8).
// Constants, strings and user rights from Microsoft Learn "Privilege
// Constants", whose string for 22 [MS-LSAD] misspells.
var privilegeByLUID = map[uint32]documentedPrivilege{
	2:  {"SE_CREATE_TOKEN_NAME", "SeCreateTokenPrivilege", "Create a token object"},
	3:  {"SE_ASSIGNPRIMARYTOKEN_NAME", "SeAssignPrimaryTokenPrivilege", "Replace a process-level token"},
	4:  {"SE_LOCK_MEMORY_NAME", "SeLockMemoryPrivilege", "Lock pages in memory"},
	5:  {"SE_INCREASE_QUOTA_NAME", "SeIncreaseQuotaPrivilege", "Adjust memory quotas for a process"},
	6:  {"SE_MACHINE_ACCOUNT_NAME", "SeMachineAccountPrivilege", "Add workstations to domain"},
	7:  {"SE_TCB_NAME", "SeTcbPrivilege", "Act as part of the operating system"},
	8:  {"SE_SECURITY_NAME", "SeSecurityPrivilege", "Manage auditing and security log"},
	9:  {"SE_TAKE_OWNERSHIP_NAME", "SeTakeOwnershipPrivilege", "Take ownership of files or other objects"},
	10: {"SE_LOAD_DRIVER_NAME", "SeLoadDriverPrivilege", "Load and unload device drivers"},
	11: {"SE_SYSTEM_PROFILE_NAME", "SeSystemProfilePrivilege", "Profile system performance"},
	12: {"SE_SYSTEMTIME_NAME", "SeSystemtimePrivilege", "Change the system time"},
	13: {"SE_PROF_SINGLE_PROCESS_NAME", "SeProfileSingleProcessPrivilege", "Profile single process"},
	14: {"SE_INC_BASE_PRIORITY_NAME", "SeIncreaseBasePriorityPrivilege", "Increase scheduling priority"},
	15: {"SE_CREATE_PAGEFILE_NAME", "SeCreatePagefilePrivilege", "Create a pagefile"},
	16: {"SE_CREATE_PERMANENT_NAME", "SeCreatePermanentPrivilege", "Create permanent shared objects"},
	17: {"SE_BACKUP_NAME", "SeBackupPrivilege", "Back up files and directories"},
	18: {"SE_RESTORE_NAME", "SeRestorePrivilege", "Restore files and directories"},
	19: {"SE_SHUTDOWN_NAME", "SeShutdownPrivilege", "Shut down the system"},
	20: {"SE_DEBUG_NAME", "SeDebugPrivilege", "Debug programs"},
	21: {"SE_AUDIT_NAME", "SeAuditPrivilege", "Generate security audits"},
	22: {"SE_SYSTEM_ENVIRONMENT_NAME", "SeSystemEnvironmentPrivilege", "Modify firmware environment values"},
	23: {"SE_CHANGE_NOTIFY_NAME", "SeChangeNotifyPrivilege", "Bypass traverse checking"},
	24: {"SE_REMOTE_SHUTDOWN_NAME", "SeRemoteShutdownPrivilege", "Force shutdown from a remote system"},
	25: {"SE_UNDOCK_NAME", "SeUndockPrivilege", "Remove computer from docking station"},
	26: {"SE_SYNC_AGENT_NAME", "SeSyncAgentPrivilege", "Synchronize directory service data"},
	27: {"SE_ENABLE_DELEGATION_NAME", "SeEnableDelegationPrivilege", "Enable computer and user accounts to be trusted for delegation"},
	28: {"SE_MANAGE_VOLUME_NAME", "SeManageVolumePrivilege", "Perform volume maintenance tasks"},
	29: {"SE_IMPERSONATE_NAME", "SeImpersonatePrivilege", "Impersonate a client after authentication"},
	30: {"SE_CREATE_GLOBAL_NAME", "SeCreateGlobalPrivilege", "Create global objects"},
	31: {"SE_TRUSTED_CREDMAN_ACCESS_NAME", "SeTrustedCredManAccessPrivilege", "Access Credential Manager as a trusted caller"},
	32: {"SE_RELABEL_NAME", "SeRelabelPrivilege", "Modify an object label"},
	33: {"SE_INC_WORKING_SET_NAME", "SeIncreaseWorkingSetPrivilege", "Increase a process working set"},
	34: {"SE_TIME_ZONE_NAME", "SeTimeZonePrivilege", "Change the time zone"},
	35: {"SE_CREATE_SYMBOLIC_LINK_NAME", "SeCreateSymbolicLinkPrivilege", "Create symbolic links"},
	36: {"SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME", "SeDelegateSessionUserImpersonatePrivilege", "Impersonate other users"},
}
