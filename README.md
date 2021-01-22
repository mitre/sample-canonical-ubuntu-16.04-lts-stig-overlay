# sample-canonical-ubuntu-16.04-lts-stig-overlay
InSpec profile overlay to validate the secure configuration of Canonical Ubuntu 16.04 LTS against [DISA's](https://public.cyber.mil/stigs/) Canonical Ubuntu 16.04 LTS STIG Version 1 Release 1.

## Getting Started  
It is intended and recommended that InSpec and this profile be run from a __"runner"__ host (such as a DevOps orchestration server, an administrative management system, or a developer's workstation/laptop) against the target [ remotely over __ssh__].
    
__For the best security of the runner, always install on the runner the _latest version_ of InSpec and supporting Ruby language components.__ 

The latest versions and installation options are available at the [InSpec](http://inspec.io/) site.

Git is required to download the latest InSpec profiles using the instructions below. Git can be downloaded from the [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) site. 

## Tailoring to Your Environment
The following inputs must be configured in an inputs ".yml" file for the profile to run correctly for your specific environment. More information about InSpec inputs can be found in the [InSpec Profile Documentation](https://www.inspec.io/docs/reference/profiles/).

```
# Emergency user accounts
emergency_accounts: []

# Temporary user accounts
temporary_accounts: []

# Known application groups
application_groups: []

# System accounts that support approved system activities
known_system_accounts: []

# Accounts that are not allowed on the system
disallowed_accounts: []

# Accounts of known managed users
user_accounts: []

# These are `home dir` exempt interactive accounts
exempt_home_users: []

# Security Personnel accounts
security_accounts: []

```

## Running This Overlay Directly from Github

```
# How to run
inspec exec https://github.com/mitre/sample-canonical-ubuntu-16.04-lts-stig-overlay/archive/main.tar.gz --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> -t ssh://<hostname>:<port> --sudo --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```

### Different Run Options

  [Full exec options](https://docs.chef.io/inspec/cli/#options-3)

## Running This Overlay from a local Archive copy 

If your runner is not always expected to have direct access to GitHub, use the following steps to create an archive bundle of this overlay and all of its dependent tests:

(Git is required to clone the InSpec profile using the instructions below. Git can be downloaded from the [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) site.)

When the __"runner"__ host uses this profile overlay for the first time, follow these steps: 

```
mkdir profiles
cd profiles
git clone https://github.com/mitre/sample-canonical-ubuntu-16.04-lts-stig-overlay.git
inspec archive sample-canonical-ubuntu-16.04-lts-stig-overlay
inspec exec <name of generated archive> --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> -t ssh://<hostname>:<port> --sudo --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```
For every successive run, follow these steps to always have the latest version of this overlay and dependent profiles:

```
cd sample-canonical-ubuntu-16.04-lts-stig-overlay
git pull
cd ..
inspec archive sample-canonical-ubuntu-16.04-lts-stig-overlay --overwrite
inspec exec <name of generated archive> --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> -t ssh://<hostname>:<port> --sudo --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```

## Using Heimdall for Viewing the JSON Results

The JSON results output file can be loaded into __[heimdall-lite](https://heimdall-lite.mitre.org/)__ for a user-interactive, graphical view of the InSpec results. 

The JSON InSpec results file may also be loaded into a __[full heimdall server](https://github.com/mitre/heimdall)__, allowing for additional functionality such as to store and compare multiple profile runs.

## Testing the Profile

The included `kitchen.yml`, `bootstrap.sh`, and `sample.input.yml` files can be used to test the overlay using [Chef Test-Kitchen](https://kitchen.ci/). Start by installing [Chef-Workstation](https://downloads.chef.io/chef-workstation), [VirtualBox](https://www.virtualbox.org/wiki/Downloads) and [Vagrant](https://www.vagrantup.com/downloads.html). Run the following commmand to test the profile:

```bash
kitchen test
```

## Contributing and Getting Help
To report a bug or feature request, please open an [issue](https://github.com/mitre/sample-canonical-ubuntu-16.04-lts-stig-overlay/issues/new).


### NOTICE 

DISA STIGs are published by DISA IASE, see: https://iase.disa.mil/Pages/privacy_policy.aspx
