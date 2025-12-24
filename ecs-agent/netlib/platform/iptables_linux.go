package platform

import (
	"fmt"
	"os/exec"

	"github.com/aws/amazon-ecs-agent/ecs-agent/logger"
	loggerfield "github.com/aws/amazon-ecs-agent/ecs-agent/logger/field"
)

// iptablesAction enumerates different actions for the iptables command
type iptablesAction string

const (
	iptablesExecutable = "iptables"
	ip6tablesExecutable = "ip6tables"
	iptablesTableNat   = "nat"
	ip6tablesTableNat  = "nat"
	sysctlExecutable   = "sysctl"
	// iptablesAppend enumerates the 'append' action
	iptablesAppend iptablesAction = "-A"
	// iptablesCheck enumerates the 'check' action
	iptablesCheck iptablesAction = "-C"

	// sysctl configuration keys
	ipForwardingKey        = "net.ipv4.ip_forward"
	ipv6ForwardingKey      = "net.ipv6.conf.all.forwarding"
	bridgeNetfilterCallKey = "net.bridge.bridge-nf-call-iptables"
	bridgeNetfilterCallIPv6Key = "net.bridge.bridge-nf-call-ip6tables"
)

// getNetfilterChainArgsFunc defines a function pointer type that returns
// a slice of arguments for modifying a netfilter chain
type getNetfilterChainArgsFunc func() []string

// modifyNetfilterEntry modifies an entry in the netfilter table based on
// the action and the function pointer to get arguments for modifying the chain
func modifyNetfilterEntry(table string, action iptablesAction, getNetfilterChainArgs getNetfilterChainArgsFunc) error {
	return modifyNetfilterEntryWithCmd(iptablesExecutable, table, action, getNetfilterChainArgs)
}

// modifyNetfilterEntryIPv6 modifies an entry in the netfilter table using ip6tables
func modifyNetfilterEntryIPv6(table string, action iptablesAction, getNetfilterChainArgs getNetfilterChainArgsFunc) error {
	return modifyNetfilterEntryWithCmd(ip6tablesExecutable, table, action, getNetfilterChainArgs)
}

// modifyNetfilterEntryWithCmd modifies an entry in the netfilter table using the specified command
func modifyNetfilterEntryWithCmd(executable, table string, action iptablesAction, getNetfilterChainArgs getNetfilterChainArgsFunc) error {
	args := append(getTableArgs(table), string(action))
	args = append(args, getNetfilterChainArgs()...)
	cmd := exec.Command(executable, args...)

	logger.Info("Executing iptables command", logger.Fields{
		"executable": executable,
		"args":       args,
		"table":      table,
		"action":     string(action),
	})

	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Error("iptables command failed", logger.Fields{
			"executable":      executable,
			"args":            args,
			"output":          string(output),
			loggerfield.Error: err,
		})
		return err
	}

	logger.Info("iptables command succeeded", logger.Fields{
		"executable": iptablesExecutable,
		"args":       args,
		"output":     string(output),
	})

	return nil
}

func getTableArgs(table string) []string {
	return []string{"-t", table}
}

// getDaemonBridgeNATArgs returns arguments for daemon-bridge MASQUERADE rule
func getDaemonBridgeNATArgs() []string {
	return []string{
		"POSTROUTING",
		"-s", ECSSubNet,
		"!", "-d", ECSSubNet,
		"-j", "MASQUERADE",
	}
}

// getDaemonBridgeNATArgsIPv6 returns arguments for daemon-bridge IPv6 MASQUERADE rule
func getDaemonBridgeNATArgsIPv6() []string {
	return []string{
		"POSTROUTING",
		"-s", ECSSubNetIPv6,
		"!", "-d", ECSSubNetIPv6,
		"-j", "MASQUERADE",
	}
}

// enableSysctlSetting enables a sysctl setting with the given key and value
func enableSysctlSetting(key string, value string) error {
	cmd := exec.Command(sysctlExecutable, "-w", fmt.Sprintf("%s=%s", key, value))
	return cmd.Run()
}

// enableSystemSettings enables required system settings for NAT
func enableSystemSettings() error {
	// Enable IPv4 forwarding
	if err := enableSysctlSetting(ipForwardingKey, "1"); err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %w", err)
	}

	// Enable IPv6 forwarding
	if err := enableSysctlSetting(ipv6ForwardingKey, "1"); err != nil {
		return fmt.Errorf("failed to enable IPv6 forwarding: %w", err)
	}

	// Enable bridge forwarding (ignore errors if bridge module not loaded)
	enableSysctlSetting(bridgeNetfilterCallKey, "1")
	enableSysctlSetting(bridgeNetfilterCallIPv6Key, "1")

	return nil
}
