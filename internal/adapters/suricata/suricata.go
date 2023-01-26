package suricata

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"lee-netflow/internal/adapters/suricata/rule/constants"
	"lee-netflow/internal/adapters/suricata/rule/element/address"
	"lee-netflow/internal/adapters/suricata/rule/element/constant"
	"lee-netflow/internal/adapters/suricata/rule/element/port"
	suricata_matcher "lee-netflow/internal/adapters/suricata/rule/matcher"
	suricata_parser "lee-netflow/internal/adapters/suricata/rule/parser"
	suricata_validator "lee-netflow/internal/adapters/suricata/rule/validator"
	"lee-netflow/internal/domain/rule/matcher"
	"lee-netflow/internal/domain/rule/parser"
	"lee-netflow/internal/domain/rule/validator"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	LOG_DEBUG_LVL = "DEBUG"
	LOG_INFO_LVL  = "INFO"
	LOG_ERROR_LVL = "ERROR"
)

type SuricataConfig struct {
	Addresses   map[string]string `json:"addresses"`
	Ports       map[string]string `json:"ports"`
	LogsDirPath string            `json:"logs_dir_path"`
	LogLevel    string            `json:"log_level"`
}

type Suricata struct {
	parser    *suricata_parser.SuricataParser
	validator *suricata_validator.SuricataValidator
	matcher   *suricata_matcher.SuricataMatcher

	logs_dir_path string
	log_file_path string
	log_level     string
	logs          *loggers
}

type loggers struct {
	debug *log.Logger
	info  *log.Logger
	err   *log.Logger
}

func (s *Suricata) loggersConfig(log_level string) (*loggers, error) {

	if _, err := os.Stat(s.logs_dir_path); os.IsNotExist(err) {
		return nil, fmt.Errorf("Directory <%s> doesnt exists", s.logs_dir_path)
	}

	if log_level != LOG_DEBUG_LVL && log_level != LOG_INFO_LVL && log_level != LOG_ERROR_LVL {
		if log_level != "" {
			return nil, fmt.Errorf("Unexpected log level %s", log_level)
		}
	}
	s.log_level = log_level

	s.log_file_path = s.logs_dir_path + "/full-" + strings.Split(time.Now().String(), " ")[0] + ".log"
	f_log, err := os.OpenFile(s.log_file_path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		return nil, err
	}

	lg := &loggers{}
	lg.debug = log.New(f_log, "[DEBUG]\t", log.Ldate|log.Ltime)
	lg.info = log.New(f_log, "[INFO]\t", log.Ldate|log.Ltime)
	lg.err = log.New(f_log, "[ERROR]\t", log.Ldate|log.Ltime)

	return lg, nil
}

func New() *Suricata {

	return &Suricata{
		parser:    suricata_parser.New(),
		matcher:   suricata_matcher.New(),
		validator: suricata_validator.New(),
	}
}

func (s *Suricata) GetParser() parser.Parser {
	return s.parser
}

func (s *Suricata) GetValidator() validator.Validator {
	return s.validator
}

func (s *Suricata) GetMatcher() matcher.Matcher {
	return s.matcher
}

func (s *Suricata) Configure(config_path string) error {
	conf_bytes, err := ioutil.ReadFile(config_path)
	if err != nil {
		return err
	}

	conf_json := SuricataConfig{}
	err = json.Unmarshal(conf_bytes, &conf_json)
	if err != nil {
		return err
	}

	if conf_json.LogsDirPath == "" {
		ex, err := os.Executable()
		if err != nil {
			return err
		}
		ex_path := filepath.Dir(ex)
		s.logs_dir_path = ex_path
	}
	s.logs_dir_path = conf_json.LogsDirPath
	s.logs, err = s.loggersConfig(conf_json.LogLevel)
	if err != nil {
		return err
	}

	if conf_json.Addresses == nil || conf_json.Ports == nil {
		return fmt.Errorf("Some troubles with parsing 'addresses' or 'ports' fields.")
	}

	for key, value := range conf_json.Addresses {
		if !constants.IsConstant(key) {
			return fmt.Errorf("Expected formatted constant. Found %s", key)
		}
		// if constant check already has this one
		if constants.IsConstant(value) {
			value_const := constant.New(value, address.New(value, constants.ConstantType))
			key_const := constant.New(key, value_const)
			if !s.validator.IsValid(value_const) {
				return fmt.Errorf("Constant %s doesnt valid", value_const.GetValue())
			}
			if !s.validator.IsAvailable(value_const) {
				return fmt.Errorf("Constant %s doesnt available", value_const.GetValue())
			}
			avl_const_el, err := s.validator.GetAvailableByElement(value_const)
			if err != nil {
				return err
			}
			key_const.SetElement(avl_const_el)
			if err = s.validator.AddValid(key_const); err != nil {
				return err
			}
			if err = s.validator.AddAvailable(key_const); err != nil {
				return err
			}
			continue
		}
		// if its ipv4
		if constants.IsIPv4(value) {
			const_addr := constant.New(key, address.New(value, constants.AddressType))
			if err = s.validator.AddValid(const_addr); err != nil {
				return err
			}
			if err = s.validator.AddAvailable(const_addr); err != nil {
				return err
			}
			continue
		}
		// if constant is group
		if constants.IsGroup(value) {
			grp, err := suricata_parser.ParseGroup(value, constants.AddressType, s.validator.GetBaseValidator())
			if err != nil {
				return err
			}
			const_grp := constant.New(key, grp)
			if err = s.validator.AddValid(const_grp); err != nil {
				return err
			}
			if err = s.validator.AddAvailable(const_grp); err != nil {
				return err
			}
			continue
		}

		return fmt.Errorf("Unexpected token %s", value)
	}
	for key, value := range conf_json.Ports {
		if !constants.IsConstant(key) {
			return fmt.Errorf("Expected formatted constant. Found %s", key)
		}
		// if constant check already has this one
		if constants.IsConstant(value) {
			value_const := constant.New(value, port.New(value, constants.ConstantType))
			key_const := constant.New(key, value_const)
			if !s.validator.IsValid(value_const) || !s.validator.IsAvailable(value_const) {
				return fmt.Errorf("Constant %s doesnt exists", value_const.GetValue())
			}
			avl_const, err := s.validator.GetAvailableByElement(value_const)
			if err != nil {
				return err
			}
			key_const.SetElement(avl_const)
			if err = s.validator.AddValid(key_const); err != nil {
				return err
			}
			if err = s.validator.AddAvailable(key_const); err != nil {
				return err
			}
		}
		// if its port
		if constants.IsPort(value) {
			const_port := constant.New(key, port.New(value, constants.PortType))
			if err = s.validator.AddValid(const_port); err != nil {
				return err
			}
			if err = s.validator.AddAvailable(const_port); err != nil {
				return err
			}
		}
		// if constant is range
		if constants.IsPortRange(value) {
			p_range, err := suricata_parser.ParseElements(value, constants.PortType, s.validator.GetBaseValidator())
			if err != nil {
				return err
			}
			const_rng := constant.New(key, p_range)
			if err = s.validator.AddValid(const_rng); err != nil {
				return nil
			}
			if err = s.validator.AddAvailable(const_rng); err != nil {
				return nil
			}
		}
		// if constant is group
		if constants.IsGroup(value) {
			group, err := suricata_parser.ParseGroup(value, constants.SrcPortType, s.validator.GetBaseValidator())
			if err != nil {
				return err
			}
			const_grp := constant.New(key, group)
			if err = s.validator.AddValid(const_grp); err != nil {
				return nil
			}
			if err = s.validator.AddAvailable(const_grp); err != nil {
				return nil
			}
		}
	}

	return nil
}

func (s *Suricata) Run() error {
	return nil
}

func (s *Suricata) DebugLog(msg string) error {
	if s.log_level == LOG_DEBUG_LVL {
		s.logs.debug.Println(msg)
	}
	return nil
}
func (s *Suricata) InfoLog(msg string) error {
	if s.log_level == LOG_DEBUG_LVL || s.log_level == LOG_INFO_LVL {
		s.logs.info.Println(msg)
	}
	return nil
}
func (s *Suricata) ErrorLog(msg string) error {
	if s.log_level == LOG_DEBUG_LVL || s.log_level == LOG_INFO_LVL || s.log_level == LOG_ERROR_LVL {
		s.logs.err.Println(msg)
	}
	return nil
}

func (s *Suricata) GetInfo() string {
	return "Suricata System Info"
}

func (s *Suricata) GetRuleFormat() string {
	return "Action Protocol SrcAddress SrcPort Direction DstAddress DstPort Options"
}
