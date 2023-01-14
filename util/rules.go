package util

import (
	"encoding/json"

	rbacv1 "k8s.io/api/rbac/v1"
)

func IsRuleEscalation(baseRules []rbacv1.PolicyRule, escalationRules []rbacv1.PolicyRule) []rbacv1.PolicyRule {
	baseRules = ExtendRules(baseRules)
	escalationRules = ExtendRules(escalationRules)
	var escalatedRules []rbacv1.PolicyRule

	for _, escalationRule := range escalationRules {
		matched := false
		for _, baseRule := range baseRules {
			if len(escalationRule.NonResourceURLs) > 0 {
				if len(baseRule.NonResourceURLs) > 0 {
					if escalationRule.NonResourceURLs[0] == baseRule.NonResourceURLs[0] {
						matched = true
						continue
					}
					continue
				}
				continue
			}
			if len(baseRule.NonResourceURLs) == 0 && escalationRule.APIGroups[0] == baseRule.APIGroups[0] && escalationRule.Resources[0] == baseRule.Resources[0] {
				if len(escalationRule.ResourceNames) > 0 {
					if len(baseRule.ResourceNames) > 0 {
						if escalationRule.ResourceNames[0] == baseRule.ResourceNames[0] {
							matched = true
							continue
						}
						continue
					}
					continue
				}
				matched = true
				continue
			}
		}
		if !matched {
			escalatedRules = append(escalatedRules, escalationRule)
		}
		matched = false
	}
	return escalatedRules
}

func ExtendRules(rules []rbacv1.PolicyRule) []rbacv1.PolicyRule {
	var extendedRules []rbacv1.PolicyRule
	for _, rule := range rules {
		for _, apiGroup := range rule.APIGroups {
			for _, resource := range rule.Resources {
				if len(rule.ResourceNames) > 0 {
					for _, resouceName := range rule.ResourceNames {
						extendedRules = AddRule(extendedRules, rbacv1.PolicyRule{
							APIGroups:     []string{apiGroup},
							Resources:     []string{resource},
							ResourceNames: []string{resouceName},
							Verbs:         rule.Verbs,
						})
					}
				} else {
					extendedRules = AddRule(extendedRules, rbacv1.PolicyRule{
						APIGroups: []string{apiGroup},
						Resources: []string{resource},
						Verbs:     rule.Verbs,
					})
				}
			}
		}
		for _, nonResourceURL := range rule.NonResourceURLs {
			extendedRules = AddRule(extendedRules, rbacv1.PolicyRule{
				NonResourceURLs: []string{nonResourceURL},
				Verbs:           rule.Verbs,
			})
		}
	}
	return extendedRules
}

func AddRule(rules []rbacv1.PolicyRule, rule rbacv1.PolicyRule) []rbacv1.PolicyRule {
	index := ContainsRule(rules, rule)
	if index >= 0 {
		rules[index].Verbs = MergeRuleVerbs(rules[index].Verbs, rule.Verbs)
		return rules
	}
	return append(rules, rule)
}

func AddRules(rules []rbacv1.PolicyRule, addRules []rbacv1.PolicyRule) []rbacv1.PolicyRule {
	for _, rule := range addRules {
		rules = AddRule(rules, rule)
	}
	return rules
}

func ContainsRule(rules []rbacv1.PolicyRule, rule rbacv1.PolicyRule) int {
	for index, loopRule := range rules {
		if len(loopRule.NonResourceURLs) > 0 {
			if len(rule.NonResourceURLs) > 0 {
				if loopRule.NonResourceURLs[0] == rule.NonResourceURLs[0] {
					return index
				}
			}
			continue
		}
		if len(loopRule.APIGroups) > 0 && len(loopRule.Resources) > 0 {
			if len(rule.APIGroups) > 0 && len(rule.Resources) > 0 {
				if loopRule.APIGroups[0] == rule.APIGroups[0] && loopRule.Resources[0] == rule.Resources[0] {
					if len(loopRule.ResourceNames) > 0 {
						if loopRule.ResourceNames[0] == rule.ResourceNames[0] {
							return index
						}
						continue
					}
					return index
				}
			}
		}
	}
	return -1
}

// This Function merges two array of verbs
func MergeRuleVerbs(verbs1 []string, verbs2 []string) []string {
	// If either verbs1 or verbs2 has the verb * we can return the rule directly
	verbs1 = ReduceVerbs(verbs1)
	verbs2 = ReduceVerbs(verbs2)
	if len(verbs1) > 0 && verbs1[0] == "*" {
		return verbs1
	}
	if len(verbs2) > 0 && verbs2[0] == "*" {
		return verbs2
	}
	verbs := verbs1
	for _, verb2 := range verbs2 {
		match := false
		for _, verb1 := range verbs1 {
			if verb1 == verb2 {
				match = true
				break
			}
		}
		if !match {
			verbs = append(verbs, verb2)
		}
		match = false
	}
	return verbs
}

// In case a verb array contains * and other verbs this functions cuts out the other verbs removes duplicates
func ReduceVerbs(verbs []string) []string {
	var reducedVerbs []string
	for index, verb := range verbs {
		if verb == "*" {
			return []string{"*"}
		}
		matched := false
		for i := index + 1; i < len(verbs); i++ {
			if verbs[i] == verb {
				matched = true
				break
			}
		}
		if !matched {
			reducedVerbs = append(reducedVerbs, verb)
		}
		matched = false

	}
	return reducedVerbs
}

func RulesToString(rules []rbacv1.PolicyRule) (string, error) {
	result, err := json.Marshal(rules)
	return string(result), err
}
