package gvisor

const shortIDLen = 12

// ContainerInfo is the runtime metadata of the container a sandbox runs.
// Environment variables are never part of it.
type ContainerInfo struct {
	ID           string            `json:"id"`
	Name         string            `json:"name,omitempty"`
	Image        string            `json:"image,omitempty"`
	Labels       map[string]string `json:"labels,omitempty"`
	PodName      string            `json:"pod,omitempty"`
	PodNamespace string            `json:"ns,omitempty"`
	PodLabels    map[string]string `json:"podlabels,omitempty"`
}

func shortID(id string) string {
	if len(id) > shortIDLen {
		return id[:shortIDLen]
	}
	return id
}
