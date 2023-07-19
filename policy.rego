package verify
import data.sarif

import future.keywords.if
import future.keywords.in


config := {
   "ruleLevel": ["note"],
   "precision": [],
   "ruleIDs": [],
   "ignore": [],
   "maxAllowed": 3
}

verify = v {
        v := {
        "allow": sarif.allow(config),
        "violations": sarif.violations(config),
            "summary": [{
            "allow": sarif.allow(config),
            #"reason":  "Errors are BIG No-No",
            "violations": count(sarif.violations(config)),
        }]
    }
}

