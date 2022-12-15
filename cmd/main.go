package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"lee-netflow/internal/adapters/suricata"
	"lee-netflow/internal/domain/system"
)

var (
	CONF_FLAG string = ""
	TEST_RULE_FLAG string = ""
	HELP_FLAG bool = false
)

const (
	TEST_RULE = "G:/Codes/MVS/Sources/Repos/vuz/lee-netflow/internal/rules/rule1.rule"
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
	var system system.ISystem = suricata.New()

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
		fmt.Printf("Configre system error: %s", err)
		return
	}
	
	rule_bytes, _ := ioutil.ReadFile(TEST_RULE_FLAG)
	rule_text := string(rule_bytes)
	rule, err := system.GetParser().Parse(rule_text)
	if err != nil {
		fmt.Printf("Rule parsing error: %s", err)
		return
	}

	fmt.Println(rule)
}