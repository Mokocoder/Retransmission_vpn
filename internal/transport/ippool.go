package transport

import (
	"fmt"
	"net"
	"sync"
)

// IPPool manages a pool of virtual IP addresses for client allocation.
type IPPool struct {
	prefix    string
	allocated map[string]int // key -> suffix
	reverse   map[int]string // suffix -> key (O(1) reverse lookup)
	available map[int]bool
	mu        sync.RWMutex
}

func NewIPPool(prefix string, start, end int) *IPPool {
	available := make(map[int]bool)
	for i := start; i <= end; i++ {
		available[i] = true
	}
	return &IPPool{
		prefix:    prefix,
		allocated: make(map[string]int),
		reverse:   make(map[int]string),
		available: available,
	}
}

func (p *IPPool) Allocate(key string) (net.IP, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if suffix, ok := p.allocated[key]; ok {
		return net.ParseIP(fmt.Sprintf("%s.%d", p.prefix, suffix)), true
	}

	for suffix := range p.available {
		delete(p.available, suffix)
		p.allocated[key] = suffix
		p.reverse[suffix] = key
		return net.ParseIP(fmt.Sprintf("%s.%d", p.prefix, suffix)), true
	}

	return nil, false
}

func (p *IPPool) Release(key string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if suffix, ok := p.allocated[key]; ok {
		delete(p.allocated, key)
		delete(p.reverse, suffix)
		p.available[suffix] = true
	}
}

// GetKeyByIP returns the session key associated with the given virtual IP.
func (p *IPPool) GetKeyByIP(ip net.IP) (string, bool) {
	parts := ip.To4()
	if parts == nil {
		return "", false
	}
	suffix := int(parts[3])

	p.mu.RLock()
	defer p.mu.RUnlock()

	key, ok := p.reverse[suffix]
	return key, ok
}
