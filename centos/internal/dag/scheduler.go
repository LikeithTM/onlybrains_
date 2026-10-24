package dag

import (
	"fmt"
	"sih2025/internal/policy"
)

func SortRules(rules []policy.Rule) ([][]policy.Rule, error) {

	uniqueRules := []policy.Rule{}
	seenIDs := make(map[string]bool)

	for _, r := range rules {
		if _, exists := seenIDs[r.ID]; exists {
			fmt.Printf("[SCHEDULER WARN] Duplicate Rule ID found and skipped: %s\n", r.ID)
			continue
		}
		seenIDs[r.ID] = true
		uniqueRules = append(uniqueRules, r)
	}
	// -------------------------------------------

	// 2. Build the Graph
	graph := make(map[string][]string)
	inDegree := make(map[string]int)
	ruleMap := make(map[string]policy.Rule)

	// Initialize
	for _, r := range uniqueRules {
		ruleMap[r.ID] = r
		inDegree[r.ID] = 0
	}

	// Populate Edges
	for _, r := range uniqueRules {
		for _, depID := range r.DependsOn {
			// Check if dependency actually exists in our filtered list
			if _, exists := ruleMap[depID]; !exists {
				// Warn but don't crash? For strict DAG, this is an error.
				// For this demo, let's ignore broken deps to keep running.
				fmt.Printf("[SCHEDULER WARN] Rule %s depends on missing rule %s. Dependency ignored.\n", r.ID, depID)
				continue
			}
			graph[depID] = append(graph[depID], r.ID)
			inDegree[r.ID]++
		}
	}

	// 3. Kahn's Algorithm for Topological Sort
	var layers [][]policy.Rule

	// Queue for rules with 0 dependencies
	queue := []string{}
	for id, degree := range inDegree {
		if degree == 0 {
			queue = append(queue, id)
		}
	}

	// Process layers
	processedCount := 0
	for len(queue) > 0 {
		var currentLayer []policy.Rule
		nextQueue := []string{}

		for _, ruleID := range queue {
			currentLayer = append(currentLayer, ruleMap[ruleID])
			processedCount++

			// Remove this rule from the graph
			for _, childID := range graph[ruleID] {
				inDegree[childID]--
				if inDegree[childID] == 0 {
					nextQueue = append(nextQueue, childID)
				}
			}
		}

		layers = append(layers, currentLayer)
		queue = nextQueue
	}

	// 4. Cycle Detection
	// Since we used uniqueRules, this math will now be correct.
	if processedCount != len(uniqueRules) {
		return nil, fmt.Errorf("circular dependency detected! Processed %d out of %d rules", processedCount, len(uniqueRules))
	}

	return layers, nil
}
