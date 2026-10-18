package main

import (
	"fmt"
	"io"
	"time"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/extract"

	"github.com/falcosecurity/plugins/plugins/gvisor/pkg/gvisor"
)

const (
	pluginID           = 999
	pluginName         = "gvisor"
	pluginSource       = "gvisor"
	pluginContact      = "github.com/falcosecurity/plugins"
	pluginDescription  = "Runtime threat detection for gVisor-sandboxed containers via gVisor Runtime Monitoring"
	requiredAPIVersion = "3.11.0"
	eventChannelSize   = 8192
)

// gvisorPlugin implements the Falco source and extractor capabilities.
// pluginID 999 is reserved for development until the registry assigns one.
type gvisorPlugin struct {
	plugins.BasePlugin
	config gvisor.Config

	cacheNum   uint64
	cacheEvent *gvisor.Event
	cacheErr   error
}

func (p *gvisorPlugin) Info() *plugins.Info {
	return &plugins.Info{
		ID:                  pluginID,
		Name:                pluginName,
		Description:         pluginDescription,
		Contact:             pluginContact,
		Version:             gvisor.PluginVersion,
		RequiredAPIVersion:  requiredAPIVersion,
		EventSource:         pluginSource,
		ExtractEventSources: []string{pluginSource},
	}
}

func (p *gvisorPlugin) InitSchema() *sdk.SchemaInfo {
	return &sdk.SchemaInfo{Schema: gvisor.InitSchema()}
}

func (p *gvisorPlugin) Init(raw string) error {
	cfg, err := gvisor.ParseConfig(raw)
	if err != nil {
		return err
	}
	p.config = cfg
	extract.SetAsync(true)
	return nil
}

func (p *gvisorPlugin) Fields() []sdk.FieldEntry {
	defs := gvisor.Fields()
	entries := make([]sdk.FieldEntry, 0, len(defs))
	for _, d := range defs {
		entries = append(entries, sdk.FieldEntry{
			Name:   d.Name,
			Type:   d.Type,
			Desc:   d.Desc,
			IsList: d.IsList,
			Arg: sdk.FieldEntryArg{
				IsRequired: d.Arg != gvisor.ArgNone,
				IsIndex:    d.Arg == gvisor.ArgIndex,
				IsKey:      d.Arg == gvisor.ArgKey,
			},
		})
	}
	return entries
}

func (p *gvisorPlugin) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
	decoded, err := p.decode(evt)
	if err != nil {
		return err
	}
	value, ok := gvisor.ExtractField(decoded, gvisor.FieldRequest{Name: req.Field(), ArgIndex: req.ArgIndex(), ArgKey: req.ArgKey()})
	if ok {
		req.SetValue(value)
	}
	return nil
}

func (p *gvisorPlugin) String(evt sdk.EventReader) (string, error) {
	decoded, err := p.decode(evt)
	if err != nil {
		return "", err
	}
	return gvisor.Describe(decoded), nil
}

func (p *gvisorPlugin) decode(evt sdk.EventReader) (*gvisor.Event, error) {
	if p.cacheEvent != nil && p.cacheNum == evt.EventNum() {
		return p.cacheEvent, p.cacheErr
	}
	data, err := io.ReadAll(evt.Reader())
	if err != nil {
		return nil, fmt.Errorf("read event %d: %w", evt.EventNum(), err)
	}
	decoded, err := gvisor.DecodeEvent(data)
	p.cacheNum, p.cacheEvent, p.cacheErr = evt.EventNum(), &decoded, err
	return p.cacheEvent, err
}

func (p *gvisorPlugin) Open(string) (source.Instance, error) {
	events := make(chan source.PushEvent, eventChannelSize)
	emit := func(data []byte, ts time.Time) bool {
		select {
		case events <- source.PushEvent{Data: data, Timestamp: ts}:
			return true
		default:
			return false
		}
	}
	src, err := gvisor.StartSource(p.config, emit, gvisor.NewExecRunner())
	if err != nil {
		return nil, err
	}
	closeSource := func() {
		src.Close()
		close(events)
	}
	instance, err := source.NewPushInstance(
		events,
		source.WithInstanceClose(closeSource),
		source.WithInstanceEventSize(gvisor.MaxPluginEventSize(p.config)),
	)
	if err != nil {
		closeSource()
		return nil, err
	}
	return instance, nil
}
