package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"lee-netflow/internal/adapters/suricata"
	"lee-netflow/internal/domain/rule"
	"lee-netflow/internal/domain/system"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var (
	CONF_FLAG string = ""
	TEST_RULE_FLAG string = ""
	HELP_FLAG bool = false
)

const (
	TEST_RULE = "G:/Codes/MVS/Sources/Repos/vuz/lee-netflow/internal/rules/rule1.rules"
)

func conf_flags() error {
	flag.StringVar(&CONF_FLAG, "config", "", "-config /full/path/to/config/file")
	flag.StringVar(&TEST_RULE_FLAG, "rule", "", "-rule /full/path/to/rule/file")
	flag.BoolVar(&HELP_FLAG, "help", false, "-help")
	
	flag.Parse()

	if HELP_FLAG && flag.NFlag() == 1 {
		return nil
	}
	if CONF_FLAG == "" {
		return fmt.Errorf("Must have '-config' flag")
	}
	if TEST_RULE_FLAG == "" {
		return fmt.Errorf("Must have '-rule' flag")
	}
	if flag.NFlag() > 3 {
		return fmt.Errorf("Invalid flags")
	}	

	return nil
}

func main() {
	var system system.SystemRuleFormat = suricata.New()

	// flags
	if err := conf_flags(); err != nil {
		fmt.Printf("Flag parsing error: %s\n", err)
		flag.Usage()
		return
	}
	if HELP_FLAG && flag.NFlag() == 1 {
		fmt.Println(system.GetInfo())
		fmt.Println("Rule Format: ", system.GetRuleFormat())
		flag.Usage()
		return
	}
	//end of flags

	if err := system.Configure(CONF_FLAG); err != nil {
		fmt.Printf("Configure system error: %s", err)
		return
	}
	
	// rule_bytes, _ := ioutil.ReadFile(TEST_RULE_FLAG)
	rule_file, err := os.OpenFile(TEST_RULE_FLAG, os.O_RDONLY, os.ModePerm)
	if err != nil {
		system.ErrorLog(err.Error())
		return
	}
	defer rule_file.Close()

	rd := bufio.NewReader(rule_file)
	rules := []*rule.Rule{}
	for {
		rule_line, _, err := rd.ReadLine()
		if err != nil {
			if err == io.EOF {
				break
			}

			system.ErrorLog(err.Error())
			return
		}
		rule_line_text := string(rule_line)
		if rule_line_text == "" {
			continue
		}
		rule_path_parts := strings.Split(TEST_RULE_FLAG, "/")
		rule_name := rule_path_parts[len(rule_path_parts)-1]
		ans, err := system.GetParser().Parse(rule_line_text, strings.TrimSuffix(rule_name, ".rules"), system.GetValidator())
		if err != nil && ans.IsRule {
			system.ErrorLog(fmt.Sprintf("Rule parsing error: %s", err))
			return
		}
		if err != nil && !ans.IsRule {
			system.DebugLog(fmt.Sprintf("Rule comment parsed: %s", rule_line_text))
			continue
		}
		if ans.IsRule {
			system.InfoLog(fmt.Sprintf("Rule %s has been parsed", ans.Rule.GetText()))
			system.DebugLog(fmt.Sprintf("Elements of rule %s: %s", ans.Rule.GetText(), ans.Rule.String()))			
		}
		rules = append(rules, ans.Rule)
	}


	// Find all devices
    devices, err := pcap.FindAllDevs()
    if err != nil {
        fmt.Printf(err.Error())
    }

    // Print device information
	// needed_device := ""
    fmt.Println("Devices found:")
	// iface, err := net.InterfaceByName(system.GetCaptureInfo().Ifaces[0])
	if err != nil {
		system.ErrorLog(err.Error())
	}
    for _, device := range devices {
		fmt.Println("\nName: ", device.Name)
        fmt.Println("Description: ", device.Description)
        fmt.Println("Devices addresses: ", device.Description)
        for _, address := range device.Addresses {
            fmt.Println("- IP address: ", address.IP)
        }
    }
	


	handler, err := pcap.OpenLive("\\Device\\NPF_{7BA3413C-D2A3-48B3-8D5C-7C13DB65CCEB}", system.GetCaptureInfo().Snaplen, system.GetCaptureInfo().Promisc, time.Duration(system.GetCaptureInfo().Timeout))
	if err != nil {
		system.ErrorLog(fmt.Sprintf("Error open capture device %s: %s", system.GetCaptureInfo().Ifaces[0], err.Error()))
		return
	}
	pk_source := gopacket.NewPacketSource(handler, handler.LinkType())
	for pk := range pk_source.Packets() {
		for _, rule := range rules {
			matched, err := system.GetMatcher().Match(pk, rule)
			if err != nil {
				system.ErrorLog(fmt.Sprintf("Rule (%s: %s) match error: %s", rule.GetName(), rule.GetText(), err))
			}
			if matched {
				system.InfoLog(fmt.Sprintf("Rule (%s: %s) has been matched with packet %s", rule.GetName(), rule.GetText(), pk.String()))
			}
			if !matched {
				system.DebugLog(fmt.Sprintf("Rule (%s: %s) hasnt been matched with packet %s", rule.GetName(), rule.GetText(), pk.String()))
			}
		}
	}

	// rule_text := string(rule_bytes)
	// rule_path_parts := strings.Split(TEST_RULE_FLAG, "/")
	// rule_name := rule_path_parts[len(rule_path_parts)-1]
	// ans, err := system.GetParser().Parse(rule_text, strings.TrimSuffix(rule_name, ".rule"))
	// if err != nil && ans.IsRule {
	// 	system.ErrorLog(fmt.Sprintf("Rule parsing error: %s", err))
	// 	return
	// }
	// if err != nil && !ans.IsRule {
	// 	system.DebugLog(fmt.Sprintf("Rule comment parsed: %s", err))
	// 	return
	// }
	// for _, r := range rules {
	// 	system.InfoLog(fmt.Sprintf("Rule %s has been parsed", r.GetName()))
	// 	fmt.Println(r)
	// }

	

}