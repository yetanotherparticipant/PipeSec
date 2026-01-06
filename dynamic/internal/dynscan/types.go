package dynscan

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
)

type Finding struct {
	Severity       Severity `json:"severity"`
	Category       string   `json:"category"`
	Description    string   `json:"description"`
	Location       string   `json:"location"`
	Recommendation string   `json:"recommendation"`
	Evidence       string   `json:"evidence,omitempty"`
}

type MappedRegion struct {
	AddrStart string `json:"addr_start"`
	AddrEnd   string `json:"addr_end"`
	Perms     string `json:"perms"`
	Offset    string `json:"offset"`
	Dev       string `json:"dev"`
	Inode     string `json:"inode"`
	Pathname  string `json:"pathname"`
}

type OpenFD struct {
	FD       string `json:"fd"`
	Target   string `json:"target"`
	Inode    string `json:"inode,omitempty"`
	Endpoint string `json:"endpoint,omitempty"`
	Proto    string `json:"proto,omitempty"`
}

type ProcMount struct {
	MountPoint string `json:"mount_point"`
	Source     string `json:"source"`
	FSType     string `json:"fs_type"`
	Root       string `json:"root,omitempty"`
}

type ProcStatus struct {
	NoNewPrivs int `json:"no_new_privs"`
	Seccomp    int `json:"seccomp"`
	TracerPID  int `json:"tracer_pid"`
	Threads    int `json:"threads"`
}

type ProcInfo struct {
	PID            int               `json:"pid"`
	Cmdline        []string          `json:"cmdline"`
	Environ        map[string]string `json:"environ"`
	Maps           []MappedRegion    `json:"maps"`
	OpenFDs        []OpenFD          `json:"open_fds"`
	Mounts         []ProcMount       `json:"mounts"`
	Cgroup         []string          `json:"cgroup"`
	Status         ProcStatus        `json:"status"`
	Capabilities   ProcCaps          `json:"capabilities"`
	Syscall        string            `json:"syscall"`
	Children       []int             `json:"children"`
	Tasks          []int             `json:"tasks"`
	ExePath        string            `json:"exe_path"`
	CWD            string            `json:"cwd"`
	Root           string            `json:"root"`
	Namespaces     map[string]string `json:"namespaces"`
	Limits         map[string]string `json:"limits"`
	CoreDumpFilter string            `json:"core_dump_filter"`
}

type ProcCaps struct {
	CapInh string `json:"cap_inh"`
	CapPrm string `json:"cap_prm"`
	CapEff string `json:"cap_eff"`
	CapBnd string `json:"cap_bnd"`
	CapAmb string `json:"cap_amb"`
}

type ProcSnapshot struct {
	Timestamp int64             `json:"timestamp_ms"`
	Procs     map[int]*ProcInfo `json:"procs"`
}
