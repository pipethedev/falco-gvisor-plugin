package gvisor

import (
	"net"
	"path"
	"strings"

	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
)

// FieldRequest names one field to extract and its optional argument.
type FieldRequest struct {
	Name     string
	ArgIndex uint64
	ArgKey   string
}

type extractorFunc func(evt *Event, req FieldRequest) (any, bool)

var pointExtractors = map[string]extractorFunc{
	fieldEvtType:        func(e *Event, _ FieldRequest) (any, bool) { return e.Point.EventType(), true },
	fieldEvtRes:         extractEvtRes,
	fieldEvtFailed:      extractEvtFailed,
	fieldEvtIsOpenRead:  openFlag(isOpenRead),
	fieldEvtIsOpenWrite: openFlag(isOpenWrite),
	fieldEvtArgFlags:    extractArgFlags,
	fieldEvtArgDomain:   extractArgDomain,
	fieldEvtArgType:     extractArgType,
	fieldEvtArgRequest:  extractArgRequest,

	fieldFDName:      fdString(func(v fdView) string { return v.name }),
	fieldFDNameRaw:   fdString(func(v fdView) string { return v.nameRaw }),
	fieldFDDirectory: fdFile(path.Dir),
	fieldFDFilename:  fdFile(path.Base),
	fieldFDType:      fdString(func(v fdView) string { return v.typ }),
	fieldFDTypeChar:  fdString(func(v fdView) string { return fdTypeChars[v.typ] }),
	fieldFDL4Proto:   fdString(func(v fdView) string { return v.l4proto }),
	fieldFDSIP:       fdIP(func(v fdView) (net.IP, uint16) { return v.sip, v.sport }, false),
	fieldFDRIP:       fdIP(func(v fdView) (net.IP, uint16) { return v.rip, v.rport }, false),
	fieldFDSPort:     fdIP(func(v fdView) (net.IP, uint16) { return v.sip, v.sport }, true),
	fieldFDRPort:     fdIP(func(v fdView) (net.IP, uint16) { return v.rip, v.rport }, true),

	fieldProcPid:        proc(func(p ProcessInfo) any { return uint64(p.Pid) }),
	fieldProcPpid:       proc(func(p ProcessInfo) any { return uint64(p.Ppid) }),
	fieldProcName:       proc(func(p ProcessInfo) any { return p.Comm }),
	fieldProcExe:        proc(func(p ProcessInfo) any { return p.Exe() }),
	fieldProcExePath:    proc(func(p ProcessInfo) any { return p.ExePath }),
	fieldProcArgs:       proc(func(p ProcessInfo) any { return p.Args() }),
	fieldProcCmdline:    proc(func(p ProcessInfo) any { return p.Cmdline() }),
	fieldProcCwd:        proc(func(p ProcessInfo) any { return p.Cwd }),
	fieldProcTTY:        proc(func(p ProcessInfo) any { return uint64(p.TTY) }),
	fieldProcUpperLayer: proc(func(p ProcessInfo) any { return p.UpperLayer }),
	fieldProcFromMemfd:  proc(func(p ProcessInfo) any { return p.FromMemfd }),
	fieldProcStdinType:  procString(func(p ProcessInfo) string { return p.StdinType }),
	fieldProcStdoutType: procString(func(p ProcessInfo) string { return p.StdoutType }),
	fieldProcStderrType: procString(func(p ProcessInfo) string { return p.StderrType }),
	fieldProcSHA256:     procString(func(p ProcessInfo) string { return p.SHA256 }),
	fieldUserUID:        proc(func(p ProcessInfo) any { return uint64(p.UID) }),
	fieldGroupGID:       proc(func(p ProcessInfo) any { return uint64(p.GID) }),
	fieldProcPName:      ancestor(1, func(p ProcessInfo) string { return p.Comm }),
	fieldProcPExePath:   ancestor(1, func(p ProcessInfo) string { return p.ExePath }),
	fieldProcPCmdline:   ancestor(1, ProcessInfo.Cmdline),
	fieldProcAName:      ancestorArg(func(p ProcessInfo) string { return p.Comm }),
	fieldProcAExePath:   ancestorArg(func(p ProcessInfo) string { return p.ExePath }),

	fieldContainerID:     containerIDField(shortID),
	fieldContainerFullID: containerIDField(func(id string) string { return id }),
	fieldContainerName:   containerString(func(c *ContainerInfo, _ FieldRequest) string { return c.Name }),
	fieldContainerImage:  containerString(func(c *ContainerInfo, _ FieldRequest) string { return c.Image }),
	fieldContainerLabel:  containerString(func(c *ContainerInfo, r FieldRequest) string { return c.Labels[r.ArgKey] }),
	fieldK8sPodName:      containerString(func(c *ContainerInfo, _ FieldRequest) string { return c.PodName }),
	fieldK8sNsName:       containerString(func(c *ContainerInfo, _ FieldRequest) string { return c.PodNamespace }),
	fieldK8sPodLabel:     containerString(func(c *ContainerInfo, r FieldRequest) string { return c.PodLabels[r.ArgKey] }),

	fieldGvisorContainerID:   containerIDField(func(id string) string { return id }),
	fieldGvisorIsExecSession: proc(func(p ProcessInfo) any { return p.IsExecSession }),
	fieldGvisorSysno:         extractSysno,
	fieldGvisorPoint:         func(e *Event, _ FieldRequest) (any, bool) { return e.Point.PointName(), true },
	fieldGvisorANames:        extractANames,
	fieldGvisorExitStatus:    extractExitStatus,
}

var statsExtractors = map[string]func(StatsSnapshot) any{
	fieldEvtType:              func(StatsSnapshot) any { return evtTypeStats },
	fieldStatsConnections:     func(s StatsSnapshot) any { return uint64(max(s.Connections, 0)) },
	fieldStatsEventsPerSecond: func(s StatsSnapshot) any { return uint64(s.EventsPerSecond) },
	fieldStatsDrops:           func(s StatsSnapshot) any { return s.TotalDrops() },
	fieldStatsDropChannelFull: func(s StatsSnapshot) any { return s.DropChannelFull },
	fieldStatsDropTruncated:   func(s StatsSnapshot) any { return s.DropTruncated },
	fieldStatsDropDecodeError: func(s StatsSnapshot) any { return s.DropDecodeError },
	fieldStatsDropSandbox:     func(s StatsSnapshot) any { return s.DropSandbox },
	fieldStatsAttachAttempts:  func(s StatsSnapshot) any { return s.AttachAttempts },
	fieldStatsAttachFailures:  func(s StatsSnapshot) any { return s.AttachFailures },
}

// ExtractField returns the value of a field for an event and whether the
// field is present. Values are string, uint64, bool, []string or net.IP.
func ExtractField(evt *Event, req FieldRequest) (any, bool) {
	if evt.Stats != nil {
		if fn, ok := statsExtractors[req.Name]; ok {
			return fn(*evt.Stats), true
		}
		return nil, false
	}
	fn, ok := pointExtractors[req.Name]
	if !ok {
		return nil, false
	}
	return fn(evt, req)
}

func syscallExit(p Point) (*pb.Exit, bool) {
	sc, ok := p.Msg.(syscallMessage)
	if !ok || sc.GetExit() == nil {
		return nil, false
	}
	return sc.GetExit(), true
}

func extractEvtRes(e *Event, _ FieldRequest) (any, bool) {
	exit, ok := syscallExit(e.Point)
	if !ok {
		return nil, false
	}
	if exit.GetErrorno() != 0 {
		return errnoName(exit.GetErrorno()), true
	}
	return evtResSuccess, true
}

func extractEvtFailed(e *Event, _ FieldRequest) (any, bool) {
	exit, ok := syscallExit(e.Point)
	if !ok {
		return nil, false
	}
	return exit.GetErrorno() != 0, true
}

func openFlag(pred func(uint32) bool) extractorFunc {
	return func(e *Event, _ FieldRequest) (any, bool) {
		open, ok := e.Point.Msg.(*pb.Open)
		if !ok {
			return nil, false
		}
		return pred(open.GetFlags()), true
	}
}

func extractArgFlags(e *Event, _ FieldRequest) (any, bool) {
	open, ok := e.Point.Msg.(*pb.Open)
	if !ok {
		return nil, false
	}
	return openFlagsString(open.GetFlags()), true
}

func extractArgDomain(e *Event, _ FieldRequest) (any, bool) {
	sock, ok := e.Point.Msg.(*pb.Socket)
	if !ok {
		return nil, false
	}
	return socketDomainString(sock.GetDomain()), true
}

func extractArgType(e *Event, _ FieldRequest) (any, bool) {
	sock, ok := e.Point.Msg.(*pb.Socket)
	if !ok {
		return nil, false
	}
	return socketTypeString(sock.GetType()), true
}

func extractArgRequest(e *Event, _ FieldRequest) (any, bool) {
	pt, ok := e.Point.Msg.(*pb.Ptrace)
	if !ok {
		return nil, false
	}
	return ptraceRequestString(pt.GetRequest()), true
}

func fdString(get func(fdView) string) extractorFunc {
	return func(e *Event, _ FieldRequest) (any, bool) {
		v, ok := fdViewOf(e.Point)
		if !ok {
			return nil, false
		}
		s := get(v)
		return s, s != ""
	}
}

func fdFile(part func(string) string) extractorFunc {
	return func(e *Event, _ FieldRequest) (any, bool) {
		v, ok := fdViewOf(e.Point)
		if !ok || !v.isFile || v.name == "" {
			return nil, false
		}
		return part(v.name), true
	}
}

func fdIP(get func(fdView) (net.IP, uint16), wantPort bool) extractorFunc {
	return func(e *Event, _ FieldRequest) (any, bool) {
		v, ok := fdViewOf(e.Point)
		if !ok {
			return nil, false
		}
		ip, port := get(v)
		if ip == nil {
			return nil, false
		}
		if wantPort {
			return uint64(port), true
		}
		return normalizeIP(ip), true
	}
}

func proc(get func(ProcessInfo) any) extractorFunc {
	return func(e *Event, _ FieldRequest) (any, bool) {
		if e.Point.Context() == nil {
			return nil, false
		}
		return get(e.Context.Process), true
	}
}

func procString(get func(ProcessInfo) string) extractorFunc {
	return func(e *Event, _ FieldRequest) (any, bool) {
		s := get(e.Context.Process)
		return s, s != ""
	}
}

func ancestorAt(e *Event, index uint64) (ProcessInfo, bool) {
	if index == 0 {
		return e.Context.Process, e.Point.Context() != nil
	}
	if index > uint64(len(e.Context.Ancestors)) {
		return ProcessInfo{}, false
	}
	return e.Context.Ancestors[index-1], true
}

func ancestor(index uint64, get func(ProcessInfo) string) extractorFunc {
	return func(e *Event, _ FieldRequest) (any, bool) {
		p, ok := ancestorAt(e, index)
		if !ok {
			return nil, false
		}
		return get(p), true
	}
}

func ancestorArg(get func(ProcessInfo) string) extractorFunc {
	return func(e *Event, req FieldRequest) (any, bool) {
		return ancestor(req.ArgIndex, get)(e, req)
	}
}

func eventContainerID(e *Event) string {
	if id := pointContainerID(e.Point); id != "" {
		return id
	}
	if e.Context.Container != nil {
		return e.Context.Container.ID
	}
	return ""
}

func containerIDField(format func(string) string) extractorFunc {
	return func(e *Event, _ FieldRequest) (any, bool) {
		id := eventContainerID(e)
		return format(id), id != ""
	}
}

func containerString(get func(*ContainerInfo, FieldRequest) string) extractorFunc {
	return func(e *Event, req FieldRequest) (any, bool) {
		if e.Context.Container == nil {
			return nil, false
		}
		s := get(e.Context.Container, req)
		return s, s != ""
	}
}

func extractSysno(e *Event, _ FieldRequest) (any, bool) {
	sysno, ok := e.Point.Sysno()
	return sysno, ok
}

func extractANames(e *Event, _ FieldRequest) (any, bool) {
	names := make([]string, 0, len(e.Context.Ancestors))
	for _, a := range e.Context.Ancestors {
		if a.Comm != "" {
			names = append(names, a.Comm)
		}
	}
	return names, true
}

func extractExitStatus(e *Event, _ FieldRequest) (any, bool) {
	switch m := e.Point.Msg.(type) {
	case *pb.TaskExit:
		return uint64(uint32(m.GetExitStatus())), true
	case *pb.ExitNotifyParentInfo:
		return uint64(uint32(m.GetExitStatus())), true
	default:
		return nil, false
	}
}

// Describe renders a short human-readable summary of an event.
func Describe(evt *Event) string {
	if evt.Stats != nil {
		return evtTypeStats
	}
	p := evt.Context.Process
	parts := []string{evt.Point.PointName(), "pid=" + uintString(uint64(p.Pid)), "proc=" + p.Comm}
	if v, ok := fdViewOf(evt.Point); ok && v.name != "" {
		parts = append(parts, "fd="+v.name)
	}
	if id := eventContainerID(evt); id != "" {
		parts = append(parts, "container="+shortID(id))
	}
	return strings.Join(parts, " ")
}
