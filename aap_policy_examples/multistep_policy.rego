# This policy combines two existing policies, the jt_naming_validation and the project_scm_branch_validation policy into a single policy to be enforced
package multistep

import data.aap_policy_examples.jt_naming_validation as job_template_name
import data.aap_policy_examples.project_scm_branch_validation as branch

default allowed = false

allowed if {
    trace(sprintf("job_template_name.allowed: %v", [job_template_name.allowed]))
    trace(sprintf("branch.allowed: %v", [branch.allowed]))
    job_template_name.allowed
    branch.allowed
}

multistep_validation := result if {
    result := {
        "allowed": allowed,
        "violations": array.concat(job_template_name.violations, branch.violations)
    }
}
