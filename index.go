package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/mattn/go-tty"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh/terminal"
)

var terminalWidth int

func init() {
	var err error
	terminalWidth, _, err = terminal.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		log.Println("Error getting terminal size:", err)
		return
	}
}

func main() {
	fmt.Print("Enter payload: ")

	t, err := tty.Open()
	if err != nil {
		fmt.Println("Error opening terminal:", err)
		return
	}
	defer t.Close()

	payload, err := t.ReadString()
	if err != nil {
		fmt.Println("Error reading from terminal:", err)
		return
	}

	// Remove the newline character from the payload
	payload = strings.TrimSpace(payload)

	fmt.Println(strings.Repeat("─", terminalWidth))

	r := decryptMain(payload)

	sensorData := r.Map["raw"].([]uint8)

	separator := strings.Split(string(sensorData[1:]), ",2,")[0] + ","

	split := strings.Split(string(sensorData), separator)[2:]

	fmt.Println("sensor_data :")
	fmt.Println("[")
	for i := 0; i < len(split); i++ {
		fmt.Printf("  %s,\n", color.GreenString("'%s'", split[i]))
	}
	fmt.Println("]")

	fmt.Println(strings.Repeat("─", terminalWidth))

	if Check(r) {
		DisplayInformation(r)
	}
}

type sensorDataStruct struct {
	SensorData string `json:"sensor_data"`
}

func decryptMain(payload string) (result OrderedMap) {
	var sensorData, prefix []byte
	var separator string
	var key1, key2 int

	var sensor sensorDataStruct
	// parse json
	if err := json.Unmarshal([]byte(payload), &sensor); err != nil {
		log.Fatal(err)
	}

	// extract keys
	keys := strings.Split(sensor.SensorData, ";")
	key1, _ = strconv.Atoi(keys[1])
	key2, _ = strconv.Atoi(keys[2])

	// Parse prefix
	sensorData = []byte(sensor.SensorData)
	encrypted := sensorData

	re := regexp.MustCompile(`(\d+;\d+;\d+;[\d,]+;)`)
	if re.Match(sensorData) {
		prefix = re.Find(sensorData)
		sensorData = sensorData[len(prefix):]
	}

	// Obfuscated strings to plaintext
	sensorData = []byte(decrypt(string(sensorData), uint32(key1)))

	sensorData = []byte(decryptInner(string(sensorData), uint32(key2)))
	raw := sensorData

	separator = strings.Split(string(sensorData[1:]), ",2,")[0] + ","

	split := strings.Split(string(sensorData), separator)[2:]

	result.Order = make([]string, 4+len(split[2:])/2)
	result.Map = make(map[string]any)

	result.Order[0] = "key"
	result.Map["key"] = split[0]

	result.Order[1] = "sensor_value"
	result.Map["sensor_value"] = split[1]

	result.Order[2] = "raw"
	result.Map["raw"] = raw

	result.Order[3] = "encrypted"
	result.Map["encrypted"] = encrypted

	orderIndex := 4
	split = split[2:]
	for i := 0; i < len(split); i += 2 {
		result.Order[orderIndex+i/2] = split[i]
		result.Map[split[i]] = split[i+1]
	}

	return result
}

type OrderedMap struct {
	Order []string
	Map   map[string]any
}

func GetTime() int64 {
	return time.Now().UnixMilli()
}

func (om *OrderedMap) UnmarshalJSON(b []byte) error {
	json.Unmarshal(b, &om.Map)

	index := make(map[string]int)
	for key := range om.Map {
		om.Order = append(om.Order, key)
		esc, _ := json.Marshal(key) //Escape the key
		index[key] = bytes.Index(b, esc)
	}

	sort.Slice(om.Order, func(i, j int) bool { return index[om.Order[i]] < index[om.Order[j]] })
	return nil
}

func (om OrderedMap) MarshalJSON() ([]byte, error) {
	var b []byte
	buf := bytes.NewBuffer(b)
	buf.WriteRune('{')
	l := len(om.Order)
	for i, key := range om.Order {
		km, err := json.Marshal(key)
		if err != nil {
			return nil, err
		}
		buf.Write(km)
		buf.WriteRune(':')
		vm, err := json.Marshal(om.Map[key])
		if err != nil {
			return nil, err
		}
		buf.Write(vm)
		if i != l-1 {
			buf.WriteRune(',')
		}
	}
	buf.WriteRune('}')
	return buf.Bytes(), nil
}
