package enricher

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/iaa-inc/gosdk"
	"github.com/iaa-inc/gosdk/admin"
)

func NewCache(api *gosdk.AdminClient, logger log.Logger) *Cache {
	c := &Cache{
		logger:      logger,
		api:         api,
		devices:     map[string]*admin.Switch{},
		ports:       map[string]*admin.Port{},
		portsByName: map[string]*admin.Port{},
		portsByIp:   map[string]*admin.Port{},
	}

	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		for ; true; <-ticker.C {
			c.update()
		}
	}()

	return c
}

type Cache struct {
	sync.RWMutex
	logger      log.Logger
	api         *gosdk.AdminClient
	devices     map[string]*admin.Switch
	ports       map[string]*admin.Port
	portsByName map[string]*admin.Port
	portsByIp   map[string]*admin.Port
}

func (c *Cache) update() {
	level.Info(c.logger).Log("msg", "Updating cache")

	// get the devices from the API
	devices, err := admin.GetSwitches(context.Background(), c.api.Client(), 100, "0")
	if err != nil {
		fmt.Printf("Error getting devices: %v\n", err)
		level.Warn(c.logger).Log("msg", "Error getting devices", "err", err)
		return
	}

	c.Lock()
	for _, device := range devices.Switches.Edges {
		c.devices[device.Node.Ipv4_address] = &device.Node.Switch
	}
	c.Unlock()

	ignored := 0

	// Run through all switches and all ports, and shove them into the cache
	for _, device := range devices.Switches.Edges {
		for _, port := range device.Node.Switch.Ports {
			consumers, ok := port.Consumer.(*admin.SwitchPortConsumerPort)
			if !ok {
				// fmt.Printf("Port %s/%s has no consumer, ignoring\n", port.Switch.Name, port.Name)
				ignored++
				continue
			}

			// Cast consumer to the type
			c.Lock()
			c.ports[consumers.Port.Service_id] = &consumers.Port
			c.Unlock()
		}
	}

	// For all ports, create a mapping entry for the port name, to allow lookup by switch_name_if_name
	for _, port := range c.ports {
		for _, sp := range port.SwitchPorts {
			c.Lock()
			c.portsByName[fmt.Sprintf("%s_%s", port.Switch.Name, sp.Name)] = port
			c.portsByIp[fmt.Sprintf("%s_%s", sp.Switch.Ipv4_address, sp.Name)] = port
			c.Unlock()
		}
	}

	level.Info(c.logger).Log("msg", "IAA Service cache updated", "devices", len(c.devices), "ports", len(c.ports), "switchPorts", len(c.portsByName), "ignoredSwitchPorts", ignored)
}

func (c *Cache) GetDevice(target string) *admin.Switch {
	return c.devices[target]
}

func (c *Cache) GetPort(id string) *admin.Port {
	return c.ports[id]
}

func (c *Cache) GetPortByIfDescr(descr string, target string) *admin.Port {
	port, ok := c.portsByName[fmt.Sprintf("%s_%s", target, descr)]
	if !ok {
		port, ok = c.portsByIp[fmt.Sprintf("%s_%s", target, descr)]
		if !ok {
			return nil
		}
	}

	return port
}
