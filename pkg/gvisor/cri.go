package gvisor

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1"
)

const (
	criTargetScheme    = "unix://"
	labelPodName       = "io.kubernetes.pod.name"
	labelPodNamespace  = "io.kubernetes.pod.namespace"
	labelContainerName = "io.kubernetes.container.name"
)

var errCRINotFound = errors.New("container not found in CRI runtime")

// CRIFetcher reads container and pod metadata over the CRI RuntimeService.
// Requests are never verbose, so the OCI spec (and its environment) is
// never returned.
type CRIFetcher struct {
	conn   *grpc.ClientConn
	client runtime.RuntimeServiceClient
}

// NewCRIFetcher returns a fetcher for the CRI socket at path. The connection
// is established lazily.
func NewCRIFetcher(path string) (*CRIFetcher, error) {
	conn, err := grpc.NewClient(criTargetScheme+path, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("cri client for %s: %w", path, err)
	}
	return &CRIFetcher{conn: conn, client: runtime.NewRuntimeServiceClient(conn)}, nil
}

// Fetch implements MetadataFetcher.
func (c *CRIFetcher) Fetch(ctx context.Context, containerID string) (*ContainerInfo, error) {
	list, err := c.client.ListContainers(ctx, &runtime.ListContainersRequest{
		Filter: &runtime.ContainerFilter{Id: containerID},
	})
	if err != nil {
		return nil, fmt.Errorf("cri list containers: %w", err)
	}
	if len(list.GetContainers()) == 0 {
		return c.fetchSandbox(ctx, containerID)
	}
	ctr := list.GetContainers()[0]
	info := &ContainerInfo{
		ID:     ctr.GetId(),
		Name:   ctr.GetMetadata().GetName(),
		Image:  ctr.GetImage().GetImage(),
		Labels: ctr.GetLabels(),
	}
	status, err := c.client.ContainerStatus(ctx, &runtime.ContainerStatusRequest{ContainerId: ctr.GetId()})
	if err == nil && status.GetStatus().GetImage().GetImage() != "" {
		info.Image = status.GetStatus().GetImage().GetImage()
	}
	if info.Name == "" {
		info.Name = ctr.GetLabels()[labelContainerName]
	}
	c.addPod(ctx, ctr.GetPodSandboxId(), info)
	return info, nil
}

func (c *CRIFetcher) fetchSandbox(ctx context.Context, sandboxID string) (*ContainerInfo, error) {
	info := &ContainerInfo{ID: sandboxID}
	if !c.addPod(ctx, sandboxID, info) {
		return nil, fmt.Errorf("%w: %s", errCRINotFound, shortID(sandboxID))
	}
	info.Name = info.PodName
	return info, nil
}

func (c *CRIFetcher) addPod(ctx context.Context, sandboxID string, info *ContainerInfo) bool {
	if sandboxID == "" {
		return false
	}
	resp, err := c.client.PodSandboxStatus(ctx, &runtime.PodSandboxStatusRequest{PodSandboxId: sandboxID})
	if err != nil {
		info.PodName = info.Labels[labelPodName]
		info.PodNamespace = info.Labels[labelPodNamespace]
		return false
	}
	meta := resp.GetStatus().GetMetadata()
	info.PodName = meta.GetName()
	info.PodNamespace = meta.GetNamespace()
	info.PodLabels = resp.GetStatus().GetLabels()
	return true
}

// Close implements MetadataFetcher.
func (c *CRIFetcher) Close() error {
	return c.conn.Close()
}
