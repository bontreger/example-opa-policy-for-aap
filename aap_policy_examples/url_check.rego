package aap_policy_examples.url_check

import rego.v1

# checks if the http request is 200 OK
issue_exists if {
    # This is set to use the source control URL of the project in AAP, and a provided extra variable, "git_issue"
    scm_url := input.project.scm_url
    issue_id := input.extra_vars.git_issue


    # This has been tested with GitLab Community, and the transformation may be different for other source control providers
    base_url := regex.replace(scm_url, "\\.git$", "")
    target_url := sprintf("%s/-/issues/%v", [base_url, issue_id])

    # Get an HTTP response code
    response := http.send({
        "method": "HEAD",
        "url": target_url,
        "timeout": "5s",
        "tls_insecure_skip_verify": true
    })
    
    # This last step evaluates to true if the response code is 200/OK, which means that issue_exists evaluates to true
    response.status_code == 200
}

# Default to false (deny) unless issue_exists is true
default allowed := false

allowed if {
    issue_exists
}

# Rule: violations
# 1. Define 'denials' as the set of error messages (Partial Set Rule)
denials contains msg if {
    # Trigger if the issue check fails
    not issue_exists
    
    # Construct a safe error message even if vars are missing
    safe_issue := object.get(input.extra_vars, "git_issue", "missing")
    safe_url := object.get(input.project, "scm_url", "missing")
    
    msg := sprintf("Git Issue #%v was not found (or did not return 200 OK) for repo: %v", [safe_issue, safe_url])
}

# 2. Define 'violations' to output the denials (Complete Rule)
# This resolves the conflict by separating the set generation from the final output variable.
default violations := []

violations := denials
