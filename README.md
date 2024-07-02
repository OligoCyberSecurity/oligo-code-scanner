
# Oligo Code Scanner

Scanning your project on each pull request can help you keep vulnerabilities out of your project.

This GitHub Action utilizes [Grype](https://github.com/anchore/grype) to compare a vulnerability scan of the target branch to a vulnerability scan of the feature branch, and will fail if there are new vulnerabilities found which do not exist in the target branch.

You will be notified of any new vulnerabilities introduced through the feature branch. You can also choose to [prevent merging](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches#require-status-checks-before-merging) if new vulnerabilities are introduced through the feature branch.

## Usage

In your project repository, create a new file `.github/workflows/oligo-scanner-pr.yml` (Adding to an existing workflow file is also possible).

Include the following in the file:

```yaml
name: Oligo Vulnerability Scanner

# Controls when the workflow will run
on:
  # Triggers the workflow on push or pull request events
  pull_request:
    branches:
      - '**'

  # Allows you to run this workflow manually from the Actions tab
  workflow_dispatch:
  
jobs:
  scan-pr:
    name: Scan comparing base and comment on pr
    runs-on: ubuntu-latest
    outputs:
      json: ${{ steps.display.outputs.json }}
    steps:
      - name: Checkout the main branch repository
        uses: actions/checkout@v4
        with:
          fetch-depth: 0
          submodules: recursive
          token: ${{ secret }}
          path: main

      - name: Checkout base branch repository
        uses: actions/checkout@v4
        with:
          fetch-depth: 0
          submodules: recursive
          ref: ${{ github.event.pull_request.base.ref }}
          token: ${{ secret }}
          path: base

      - name: Scan both feature & main branches and compare output differences
        id: scan
        uses: OligoCyberSecurity/oligo-code-scanner@v1.0.7
        continue-on-error: true
        with:
          path: './main'
          base-path: './base'
          fail-build: true
          severity-cutoff: high
          output-format: json
```

## Examples

Oligo scanner saves the results in the jobs's `outputs` variable in JSON, SARIF, MD formats.
You can use the result of Oligo scanner in order to comment on the PR, upload to the workflow [Artifacts](https://docs.github.com/en/actions/using-workflows/storing-workflow-data-as-artifacts), or even open new GitHub Issue in your account.

### Commenting PR]

![alt text](https://github.com/OligoCyberSecurity/oligo-code-scanner/assets/112797342/a1c8eda2-42ce-4fb1-a55f-fdf83686625a "Title")

Adding the next code to your workflow file will comment the results of the action in the PR:

```yaml
      - name: Add Oligo scanning results on Pull-request
        if: ${{ steps.scan.outcome != 'success' }}
        uses: mshick/add-pr-comment@v1
        with:
          message: |
            New vulnerabilites detected:
            ${{steps.scan.outputs.markdown}}
          repo-token: ${{ secret }}
          allow-repeats: false # Set to true to comment on every run
```

### Prevent Merging PR

Setting `fail-build`  to `true` will cause the action to fail. In order to block PR from being merged when there is a new vulnerability, you need to change your repository setting and [add a new status check](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches#require-status-checks-before-merging).

## Arguments

|Argument  |Description |Default |Required | Options |
|--|--|--|--|--|
| `only-fixed` | Specify whether to only report vulnerabilities that have a fix available. |  `false`| :x: | `false`, `true`|
| `severity-cutoff` |  Optionally specify the minimum vulnerability severity to trigger an "error" level ACS result. Any vulnerability with a severity less than this value will lead to a "warning" result.  Default is "medium".| `medium`| :x: | `negligible`, `low`, `medium`, `high`, `critical` |
| `output-format` | Set the output parameter after successful action execution.  | `json` |:x:| `json`, `sarif`, `table` |
| `fail-build` |Set to false to avoid failing based on severity-cutoff. | `true`  | :x: | `true`, `false` |
| `path` | The path of the checked-out feature branch to scan. | `.` | :white_check_mark:  | Any valid path |
| `base-path` | The path of the target branch to scan. This is the path that will be used to resolve the difference with the feature branch code. |  `.`|:x:  | Any valid path |
