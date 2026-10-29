// dispatchctl sends native app requests over the owner's private socket.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type operation struct {
	positions string
	flags     string
	required  string
}

// flag:field maps convenient CLI names onto the wire contract; # means integer.
var operations = map[string]operation{
	"jobs":    {flags: "state lane prefix:job_key_prefix page#"},
	"job":     {positions: "job_id"},
	"trace":   {positions: "job_id"},
	"wait":    {positions: "job_id"},
	"lookup":  {positions: "submission_key"},
	"fleet":   {},
	"stats":   {flags: "window:window_s#"},
	"budget":  {},
	"cancel":  {positions: "job_id", flags: "reason"},
	"approve": {positions: "job_id", flags: "author reason", required: "author"},
	"reject":  {positions: "job_id", flags: "author reason", required: "author"},
	"ack":     {positions: "job_id disposition", flags: "reason"},
	"sweep":   {},
	"enqueue": {flags: "key:job_key lane inv:invocation_address cost:cost_estimate_usd submission:submission_key", required: "job_key lane invocation_address"},
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "dispatchctl:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	global := flag.NewFlagSet("dispatchctl", flag.ContinueOnError)
	addr := global.String("addr", "", "private app address: unix:/path or host:port")
	global.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: dispatchctl -addr ADDRESS COMMAND [arguments] [--flags]\ncommands: jobs job trace wait lookup fleet stats budget cancel approve reject ack sweep enqueue\nAll commands print the native JSON result. COMMAND --help lists its arguments.")
	}
	if err := global.Parse(args); err != nil {
		return err
	}
	if *addr == "" || global.NArg() == 0 {
		global.Usage()
		return errors.New("address and command required")
	}
	typ, body, err := request(global.Arg(0), global.Args()[1:])
	if err != nil {
		return err
	}
	c, err := dial(*addr)
	if err != nil {
		return err
	}
	defer c.close()
	env, err := c.call(typ, body)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(json.RawMessage(env.Body))
}

func request(name string, args []string) (string, map[string]any, error) {
	op, ok := operations[name]
	if !ok {
		return "", nil, fmt.Errorf("unknown command %q", name)
	}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	values := map[string]*string{}
	fields := map[string]string{}
	for _, descriptor := range strings.Fields(op.flags) {
		flagName, field, mapped := strings.Cut(descriptor, ":")
		if !mapped {
			flagName = strings.TrimSuffix(descriptor, "#")
			field = descriptor
		}
		fields[flagName] = field
		values[flagName] = fs.String(flagName, "", field)
	}
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s %s [flags]\n", name, op.positions)
		fs.PrintDefaults()
	}
	// Allow options on either side of positional arguments.
	var options, positions []string
	for i := 0; i < len(args); i++ {
		if strings.HasPrefix(args[i], "-") {
			options = append(options, args[i])
			if !strings.Contains(args[i], "=") && strings.TrimLeft(args[i], "-") != "help" && i+1 < len(args) {
				i++
				options = append(options, args[i])
			}
		} else {
			positions = append(positions, args[i])
		}
	}
	if err := fs.Parse(options); err != nil {
		return "", nil, err
	}
	keys := strings.Fields(op.positions)
	if len(positions) != len(keys) {
		return "", nil, fmt.Errorf("%s requires %s", name, op.positions)
	}
	body := map[string]any{}
	for i, key := range keys {
		body[key] = positions[i]
	}
	for key, value := range values {
		if *value == "" {
			continue
		}
		field := fields[key]
		if strings.HasSuffix(field, "#") {
			number, err := strconv.Atoi(*value)
			if err != nil {
				return "", nil, fmt.Errorf("--%s requires an integer", key)
			}
			body[strings.TrimSuffix(field, "#")] = number
		} else {
			body[field] = *value
		}
	}
	for _, key := range strings.Fields(op.required) {
		if body[key] == nil {
			return "", nil, fmt.Errorf("%s requires %s", name, key)
		}
	}
	if name == "jobs" {
		filter := map[string]any{}
		for _, key := range []string{"state", "lane", "job_key_prefix"} {
			if value, found := body[key]; found {
				filter[key] = value
				delete(body, key)
			}
		}
		body["filter"] = filter
	}
	if name == "enqueue" {
		return name, map[string]any{"jobs": []any{body}}, nil
	}
	if name == "trace" {
		name = "job"
	}
	return name, body, nil
}
