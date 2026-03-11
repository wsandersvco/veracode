<img src="imgs/vclogo-light-mode.png#gh-light-mode-only">
<img src="imgs/vclogo-dark-mode.png#gh-dark-mode-only">

## Veracode GitHub Workflow Integration 

The Veracode GitHub Workflow Integration allows you to set up a security scanning program for all of your GitHub repositories in a single configuration file.

This repository includes the workflows required for the GitHub Workflow Integration to function correctly. In addition, it includes the configuration file, `veracode.yml`, which stores the default settings for you to scan your repositories with Veracode.

For guidance on installing the Veracode Workflow Application and additional information about the integration, please view the Veracode documentation.
https://docs.veracode.com/r/GitHub_Workflow_Integration_for_Repo_Scanning

## Updates
1. Add the official Veracode GitHub Actions Integration repository as an upstream remote: https://github.com/veracode/github-actions-integration
2. Fetch the upstream changes.
3. Merge upstream/main into a feature branch.
    - `git checkout -b <feature/branch>`
    - `git merge upstream/main`
4. Open a PR into the repository’s main branch to review and resolve any conflicts.
5. Merge and validate.

## Cherry-pick
1. Create local feature branch off main.
    - `git checkout origin/main`
    - `git branch <feature/branch>`
2. `git restore --patch --source=<feature/branch> -- <folder>`
3. `git commit -m <commit message>`
4. `git push`
4. Open a PR into the repository's main branch to review and resolve conflicts.