package gvisor

import (
	"strconv"

	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
)

//go:generate go run ../../tools/gensysno -out . -pkg gvisor

const (
	evtTypeContainerStart   = "container_start"
	evtTypeSentryClone      = "sentry_clone"
	evtTypeSentryExecve     = "sentry_execve"
	evtTypeTaskExit         = "task_exit"
	evtTypeExitNotifyParent = "exit_notify_parent"
	evtTypeStats            = "gvisor_stats"
	evtTypeUnknownSyscall   = "syscall_"
	pointPrefixSyscall      = "syscall/"
	pointSuffixEnter        = "/enter"
	pointSuffixExit         = "/exit"
)

var sentryPoints = map[pb.MessageType]struct{ evtType, point string }{
	pb.MessageType_MESSAGE_CONTAINER_START:           {evtTypeContainerStart, "container/start"},
	pb.MessageType_MESSAGE_SENTRY_CLONE:              {evtTypeSentryClone, "sentry/clone"},
	pb.MessageType_MESSAGE_SENTRY_EXEC:               {evtTypeSentryExecve, "sentry/execve"},
	pb.MessageType_MESSAGE_SENTRY_TASK_EXIT:          {evtTypeTaskExit, "sentry/task_exit"},
	pb.MessageType_MESSAGE_SENTRY_EXIT_NOTIFY_PARENT: {evtTypeExitNotifyParent, "sentry/exit_notify_parent"},
}

func syscallName(sysno uint64) string {
	if name, ok := syscallNames[sysno]; ok {
		return name
	}
	return evtTypeUnknownSyscall + strconv.FormatUint(sysno, 10)
}

// EventType returns the Falco-style evt.type of the point.
func (p Point) EventType() string {
	if sp, ok := sentryPoints[p.Type]; ok {
		return sp.evtType
	}
	if sc, ok := p.Msg.(syscallMessage); ok {
		return syscallName(sc.GetSysno())
	}
	return p.Type.String()
}

// PointName returns the gVisor trace point name, e.g. syscall/connect/exit.
func (p Point) PointName() string {
	if sp, ok := sentryPoints[p.Type]; ok {
		return sp.point
	}
	sc, ok := p.Msg.(syscallMessage)
	if !ok {
		return p.Type.String()
	}
	suffix := pointSuffixEnter
	if sc.GetExit() != nil {
		suffix = pointSuffixExit
	}
	return pointPrefixSyscall + syscallName(sc.GetSysno()) + suffix
}

// Sysno returns the syscall number, and false for non-syscall points.
func (p Point) Sysno() (uint64, bool) {
	if sc, ok := p.Msg.(syscallMessage); ok {
		return sc.GetSysno(), true
	}
	return 0, false
}

// SyscallNumber returns the syscall number of name on the build architecture.
func SyscallNumber(name string) (uint64, bool) {
	for nr, n := range syscallNames {
		if n == name {
			return nr, true
		}
	}
	return 0, false
}
