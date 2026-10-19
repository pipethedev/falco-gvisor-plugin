package gvisor

import (
	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
)

// redactArgs keeps only argv[0] in a freshly decoded point and re-encodes
// its raw packet when anything was removed, so arguments never reach Falco.
func redactArgs(p Point) (Point, error) {
	changed := false
	switch m := p.Msg.(type) {
	case *pb.ExecveInfo:
		m.Argv, changed = firstArgOnly(m.Argv)
	case *pb.Execve:
		m.Argv, changed = firstArgOnly(m.Argv)
	case *pb.Start:
		m.Args, changed = firstArgOnly(m.Args)
	}
	if !changed {
		return p, nil
	}
	if err := p.reencode(); err != nil {
		return Point{}, err
	}
	return p, nil
}

func firstArgOnly(argv []string) ([]string, bool) {
	if len(argv) <= 1 {
		return argv, false
	}
	return argv[:1], true
}
