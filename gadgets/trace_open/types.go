package trace_open

import "C"

// GadgetCreds represents the C struct gadget_creds.
type GadgetCreds struct {
	Uid uint32 // Corresponds to gadget_uid
	Gid uint32 // Corresponds to gadget_gid
}

// GadgetParent represents the C struct gadget_parent.
type GadgetParent struct {
	// Comm is the parent process name, sized by TASK_COMM_LEN in C.
	Comm string
	Pid  uint32 // Corresponds to gadget_ppid
}

// GadgetProcess represents the C struct gadget_process.
// It contains nested structs for credentials and parent process info.
type GadgetProcess struct {
	// Comm is the process name, sized by TASK_COMM_LEN in C.
	Comm    string
	Pid     uint32 // Corresponds to gadget_pid
	Tid     uint32 // Corresponds to gadget_tid
	MntnsID uint64 // Corresponds to gadget_mntns_id
	Creds   GadgetCreds
	Parent  GadgetParent
}

// GadgetUserStack represents the C struct gadget_user_stack.
type GadgetUserStack struct {
	ExeInode    uint64 // Corresponds to __u64 exe_inode
	MtimeSec    uint64 // Corresponds to __u64 mtime_sec
	MtimeNsec   uint32 // Corresponds to __u32 mtime_nsec
	StackID     uint32 // Corresponds to __u32 stack_id
	PidLevel0   uint32 // Corresponds to __u32 pid_level0
	PidnsLevel0 uint32 // Corresponds to __u32 pidns_level0
	PidLevel1   uint32 // Corresponds to __u32 pid_level1
	PidnsLevel1 uint32 // Corresponds to __u32 pidns_level1
}

// Event represents the C struct event.
// It uses standard Go types to map the C data types.
type Event struct {
	TimestampRaw uint64 // Represents C's gadget_timestamp
	Proc         GadgetProcess

	ErrorRaw int32  // Represents C's gadget_errno
	Fd       uint32 // Represents C's __u32
	FlagsRaw uint32 // Represents C's gadget_file_flags
	ModeRaw  uint32 // Represents C's gadget_file_mode
	Ustack   GadgetUserStack
	Fname    string // Represents C's char fname[NAME_MAX]
}
