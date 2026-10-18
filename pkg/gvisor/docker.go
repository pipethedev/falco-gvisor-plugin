package gvisor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

const (
	dockerHost          = "http://docker"
	dockerInspectPath   = "/containers/%s/json"
	dockerMaxBodyBytes  = 1 << 20
	dockerNamePrefix    = "/"
	networkUnix         = "unix"
	dockerInspectMethod = http.MethodGet
)

// dockerInspect lists the only fields read from the Engine API. It has no
// field for Config.Env, so environment variables are never decoded.
type dockerInspect struct {
	ID     string `json:"Id"`
	Name   string `json:"Name"`
	Config struct {
		Image  string            `json:"Image"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
}

// DockerFetcher reads container metadata from the Docker Engine API.
type DockerFetcher struct {
	client *http.Client
}

// NewDockerFetcher returns a fetcher talking to the Docker socket at path.
func NewDockerFetcher(path string) *DockerFetcher {
	dialer := &net.Dialer{}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, networkUnix, path)
		},
	}
	return &DockerFetcher{client: &http.Client{Transport: transport}}
}

// Fetch implements MetadataFetcher.
func (d *DockerFetcher) Fetch(ctx context.Context, containerID string) (*ContainerInfo, error) {
	endpoint := dockerHost + fmt.Sprintf(dockerInspectPath, url.PathEscape(containerID))
	req, err := http.NewRequestWithContext(ctx, dockerInspectMethod, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build docker request: %w", err)
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("docker inspect: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("docker inspect: unexpected status %s", resp.Status)
	}
	var inspect dockerInspect
	if err := json.NewDecoder(io.LimitReader(resp.Body, dockerMaxBodyBytes)).Decode(&inspect); err != nil {
		return nil, fmt.Errorf("decode docker inspect: %w", err)
	}
	id := inspect.ID
	if id == "" {
		id = containerID
	}
	return &ContainerInfo{
		ID:     id,
		Name:   strings.TrimPrefix(inspect.Name, dockerNamePrefix),
		Image:  inspect.Config.Image,
		Labels: inspect.Config.Labels,
	}, nil
}

// Close implements MetadataFetcher.
func (d *DockerFetcher) Close() error {
	d.client.CloseIdleConnections()
	return nil
}
