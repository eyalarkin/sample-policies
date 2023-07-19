package policy

import input.evidence.predicate.content as results
import future.keywords.if
import future.keywords.in

default allow = false
default violations = []

config := {
   "ruleLevel": ["note"],
   "precision": [],
   "ruleIDs": [],
   "ignore": [],
   "maxAllowed": 10
}

get_rules(output_file) = rules {
   rules := output_file.runs[0].tool.driver.rules
}

get_results(output_file) = results {
   results := output_file.runs[0].results
}

filtered_runs(ids, levels, precisions, ignore, of) = { id |
   rules = get_rules(of)
   rule = rules[_]
   id_check(rule.id, ids)
   # rule.id in config.ruleIDs
   level_check(rule.defaultConfiguration.level, levels)
   # rule.defaultConfiguration.level in config.ruleLevel;
   precision_check(rule.properties.precision, precisions)
   # rule.properties.precision in config.precision;
   ignore_check(rule.id, ignore)
   # not (rule.id in config.ignore);
   id = rule.id
} if { not (ignore == "all") } else := []

level_check (level, filters) {
   count(filters) == 0
}

level_check (level, filters) {
   level in filters
}

precision_check (precision, filters) {
   count(filters) == 0
}

precision_check (precision, filters) {
   precision in filters
}

id_check (id, filters) {
   count(filters) == 0
}

id_check (id, filters) {
   id in filters
}

ignore_check (ignore, filters) {
   count(filters) == 0
}

ignore_check (ignore, filters) {
   not (ignore in filters)
}

filter_list (ids, levels, precisions, ignore, of) = { summary |
   result = of.runs[0].results[_]
   lst := filtered_runs(ids, levels, precisions, ignore, of)
   result.ruleId in lst
   summary = {
      "------------------": "------------------",
      "ruleID": result.ruleId,
      "file": result.locations[0].physicalLocation.artifactLocation.uri,
      "region": result.locations[0].physicalLocation.region,
      "message": result.message.text,
   }
} if { count(filtered_runs(ids, levels, precisions, ignore, of)) > 0 } else := []

violations = res {
   res := filter_list(config.ruleIDs, config.ruleLevel, config.precision, config.ignore, results)
}

allow {
   count(violations) <= config.maxAllowed
}

verify = v {
        v := {
        "allow": allow,
        "violations": violations,
            "summary": [{
            "allow": allow,
            "reason":  "Errors are BIG No-No",
            "violations": count(violations),
        }]
    }
}
