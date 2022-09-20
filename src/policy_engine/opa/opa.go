package main

import "C"

import (
	"context"
	"encoding/json"

	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage/inmem"
)

//export evaluateGo
func evaluateGo(policy string, data string, input string) *C.char {
	// Deserialize the message in json format
	input_map := make(map[string]interface{})
	err := json.Unmarshal([]byte(input), &input_map)
	if err != nil {
		return C.CString("Error:: " + err.Error())
	}

	data_map := make(map[string]interface{})
	err2 := json.Unmarshal([]byte(data), &data_map)
	if err2 != nil {
		return C.CString("Error:: " + err.Error())
	}
	// Manually create the storage layer. inmem.NewFromObject returns an
	// in-memory store containing the supplied data.
	store := inmem.NewFromObject(data_map)

	// Construct a Rego object that can be prepared or evaluated.
	r := rego.New(
		rego.Query("input;data.policy"),
		rego.Module("policy.rego", policy),
		rego.Store(store),
	)

	// Create a prepared query that can be evaluated.
	ctx := context.Background()
	query, err := r.PrepareForEval(ctx)
	if err != nil {
		return C.CString("Error:: " + err.Error())
	}

	// Make opa query
	rs, err := query.Eval(ctx, rego.EvalInput(input_map))
	if err != nil {
		return C.CString("Error:: " + err.Error())
	}

	dataOPA, ok := rs[0].Expressions[1].Value.(map[string]interface{})
	if !ok {
		return C.CString("Error:: unexpected type in second expression")
	}

	decisionMap := make(map[string]interface{})
	// OPA's evaluation results.
	for k, v := range dataOPA {
		decisionMap[k] = v
	}

	decision, err := json.Marshal(decisionMap)
	if err != nil {
		return C.CString("Error:: " + err.Error())
	}

	return C.CString(string(decision))
}

func main() {}
