# This is an alternate approach for enforcing a job template naming validation using fixed, allowed keywords.
# Documentation for this alternate policy is in the 8.Enforce Job Template Naming Standards document
package aap_policy_examples

import rego.v1

allowed_keywords := {"DEV", "TEST", "PROD", "ALL"}

default job_template_name := {
    "allowed": true,
    "violations": [],
}

job_template_name := result if {
    jt_name := object.get(input, ["job_template", "name"], "")
    keyword := allowed_keywords[_]
    startswith(jt_name, keyword)
    result := {
        "allowed": false,
        "violations": [sprintf("Job template naming for '%v' does not comply with standards", [jt_name])]
    }
}
