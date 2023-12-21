# Oligo Code Scanner

Scanning your project on each pull request can help you keep vulnerabilities out of your project.

This GitHub Action uses [OSV Scanner](https://google.github.io/osv-scanner/) to compare a vulnerability scan of the target branch to a vulnerability scan of the feature branch, and will fail if there are new vulnerabilities found which doesn’t exist in the target branch.

You will be notified of any new vulnerabilities introduced through the feature branch. You can also choose to [prevent merging](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches#require-status-checks-before-merging) if new vulnerabilities are introduced through the feature branch.

## Usage

In your project repository, create a new file `.github/workflows/oligo-scanner-pr.yml` (Adding to an existing workflow file is also possible).

Include the following in the file:

    name: Oligo PR Scan

    # Change "main" to your default branch if you use a different name, i.e. "master"
    on:
      pull_request:
        branches: [ main ]
      merge_group:
        branches: [ main ]

    permissions:
      # Require writing security events to upload SARIF file to security tab
      security-events: write
      # Only need to read contents
      contents: read

    jobs:
      scan-pr:
        uses: "OligoCyberSecurity/oligo-code-scanner@v1.0.1"

Custom overrides and usage examples can be found in [OSV documentation](cloudposse/github-action-aws-region-reduction-map@0.2.1).

### Using Result Files

Results containing the new vulnerable packages will be logged out in the workflow run logs, but also may be viewed by clicking the output files in the [Artifacts section](https://docs.github.com/en/actions/managing-workflow-runs/downloading-workflow-artifacts) of the the failed run screen.
