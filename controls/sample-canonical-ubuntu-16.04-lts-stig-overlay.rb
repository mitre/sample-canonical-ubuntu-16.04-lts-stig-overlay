
include_controls 'canonical-ubuntu-16.04-lts-stig-baseline' do

    control 'V-75871' do
	describe file('/etc/nsswitch.conf') do
    	    it { should exist }
  	end

  	options = {
    	    assignment_regex: /^\s*([^:]*?)\s*:\s*(.*?)\s*$/
  	}

  	dns_entry_exists = parse_config_file('/etc/nsswitch.conf', options).params('hosts')
	
  	if dns_entry_exists
    	    describe 'DNS entry exists in /etc/nsswitch.conf' do
      	        subject { dns_entry_exists.match?(/dns/) }
      		it { should be true }
    	    end
  	else
    	    describe file('/etc/resolv.conf') do
     	        its('content') { should match %r{/^(?!(#.*)).+/m} }
            end
        end     
    end
    control 'V-75461' do
        non_interactive_shells = input('non_interactive_shells')
        ignore_shells = non_interactive_shells.join('|')
        counter = 0

        # If shell is nil we should note that
        bad_users = users.where { shell == nil }.raw_data.map { |user_hash| user_hash[:username] }
        describe 'Specified shell for users in /etc/passwd' do
            it 'should specify a shell' do
                failure_message = "Users without shells set: #{bad_users.join(', ')}"
                expect(bad_users).to be_empty, failure_message
            end
        end
    
        users.where { shell != nil && !shell.match(ignore_shells) }.entries.each do |user_info|
            shadow.where(user: user_info.username).passwords.each do |user_pwd|
                pwd_should_be_evaluated = !(user_pwd.casecmp?('!') || user_pwd.casecmp?('*'))
                next unless pwd_should_be_evaluated
    
                describe (user_info.username + ' - user\'s password hash') do
                    subject { user_pwd }
                    it { should start_with '$6'} 
                end
                counter += 1
            end
        end
        if counter == 0
            describe 'Number of interactive users on the system' do
            subject { counter }
                it { should be 0 }
            end
        end
    end
    control 'V-75559' do
        exempt_home_users = input('exempt_home_users')
        non_interactive_shells = input('non_interactive_shells')
        ignore_shells = non_interactive_shells.join('|')
    
        # If shell is nil we should note that
        bad_users = users.where { shell == nil }.raw_data.map { |user_hash| user_hash[:username] }
        describe 'Specified shell for users in /etc/passwd' do
            it 'should specify a shell' do
                failure_message = "Users without shells set: #{bad_users.join(', ')}"
                expect(bad_users).to be_empty, failure_message
            end
        end
        users.where { (shell != nil && !shell.match(ignore_shells)) && (uid >= 1000 || uid == 0) }.entries.each do |user_info|
            next if exempt_home_users.include?(user_info.username.to_s)
    
            describe directory(user_info.home) do
                it { should exist }
            end
        end
    end
    control 'V-75563' do
        exempt_home_users = input('exempt_home_users')
        non_interactive_shells = input('non_interactive_shells')
        ignore_shells = non_interactive_shells.join('|')

    	# If shell is nil we should note that
        bad_users = users.where { shell == nil }.raw_data.map { |user_hash| user_hash[:username] }
        describe 'Specified shell for users in /etc/passwd' do
            it 'should specify a shell' do
                failure_message = "Users without shells set: #{bad_users.join(', ')}"
                expect(bad_users).to be_empty, failure_message
            end
        end
        users.where { (shell != nil && !shell.match(ignore_shells)) && (uid >= 1000 || uid == 0) }.entries.each do |user_info|
            next if exempt_home_users.include?(user_info.username.to_s)
    
            describe directory(user_info.home) do
                it { should exist }
            end
        end
    end
    control 'V-75565' do
        exempt_home_users = input('exempt_home_users')
        non_interactive_shells = input('non_interactive_shells')
        ignore_shells = non_interactive_shells.join('|')
    
        findings = Set[]
        # If shell is nil we should note that
        bad_users = users.where { shell == nil }.raw_data.map { |user_hash| user_hash[:username] }
        describe 'Specified shell for users in /etc/passwd' do
            it 'should specify a shell' do
                failure_message = "Users without shells set: #{bad_users.join(', ')}"
                expect(bad_users).to be_empty, failure_message
            end
        end
        users.where { (shell != nil && !shell.match(ignore_shells)) && (uid >= 1000 || uid == 0) }.entries.each do |user_info|
            next if exempt_home_users.include?(user_info.username.to_s)
    
            findings += command("find #{user_info.home} -maxdepth 0 -perm /027").stdout.split("\n")
        end
        describe 'Home directories with excessive permissions' do
            subject { findings.to_a }
            it { should be_empty }
        end
    end
    control 'V-75567' do
        exempt_home_users = input('exempt_home_users')
        non_interactive_shells = input('non_interactive_shells')
        ignore_shells = non_interactive_shells.join('|')
      
        # If shell is nil we should note that
        bad_users = users.where { shell == nil }.raw_data.map { |user_hash| user_hash[:username] }
        describe 'Specified shell for users in /etc/passwd' do
            it 'should specify a shell' do
                failure_message = "Users without shells set: #{bad_users.join(', ')}"
                expect(bad_users).to be_empty, failure_message
            end
        end
        
        findings = Set[]
        users.where { (shell != nil && !shell.match(ignore_shells)) && (uid >= 1000 || uid == 0) }.entries.each do |user_info|
          next if exempt_home_users.include?(user_info.username.to_s)
      
          findings += command("find #{user_info.home} -maxdepth 0 -not -gid #{user_info.gid}").stdout.split("\n")
        end
        describe "Home directories that are not group-owned by the user's primary GID" do
          subject { findings.to_a }
          it { should be_empty }
        end
    end
    control 'V-75569' do
        non_interactive_shells = input('non_interactive_shells')
        ignore_shells = non_interactive_shells.join('|')
    	
        # If shell is nil we should note that
        bad_users = users.where { shell == nil }.raw_data.map { |user_hash| user_hash[:username] }
        describe 'Specified shell for users in /etc/passwd' do
            it 'should specify a shell' do
                failure_message = "Users without shells set: #{bad_users.join(', ')}"
                expect(bad_users).to be_empty, failure_message
            end
        end

        findings = Set[]
        users.where { (shell != nil && !shell.match(ignore_shells)) && (uid >= 1000 || uid == 0) }.entries.each do |user_info|
            dot_files = command("find #{user_info.home} -xdev -maxdepth 1 -name '.*' -type f").stdout.split("\n")
            dot_files.each do |dot_file|
            next unless file(dot_file).more_permissive_than?('0740')
    
            findings << dot_file
            end
        end
        describe 'All local initialization files have a mode of 0740 or less permissive' do
            subject { findings.to_a }
            it { should be_empty }
        end
    end
    control 'V-75571' do
        exempt_home_users = input('exempt_home_users')
        non_interactive_shells = input('non_interactive_shells')
        ignore_shells = non_interactive_shells.join('|')
    
        findings = Set[]
        # If shell is nil we should note that
        bad_users = users.where { shell == nil }.raw_data.map { |user_hash| user_hash[:username] }
        describe 'Specified shell for users in /etc/passwd' do
            it 'should specify a shell' do
                failure_message = "Users without shells set: #{bad_users.join(', ')}"
                expect(bad_users).to be_empty, failure_message
            end
        end
        users.where { (shell != nil && !shell.match(ignore_shells)) && (uid >= 1000 || uid == 0) }.entries.each do |user_info|
            next if exempt_home_users.include?(user_info.username.to_s)
    
            grep_results = command("grep -i path --exclude=\".bash_history\" #{user_info.home}/.*").stdout.split('\\n')
            grep_results.each do |result|
            result.slice! 'PATH='
            result += ' ' if result[-1] == ':'
            result.slice! '$PATH:'
            result.slice! "$PATH\"\n"
            result.gsub! '$HOME', user_info.home.to_s
            result.gsub! '~', user_info.home.to_s
            line_arr = result.split(':')
            line_arr.delete_at(0)
            line_arr.each do |line|
                line.slice! '"'
                next unless !line.start_with?('export') && !line.start_with?('#')
    
                if line.strip.empty?
                curr_work_dir = command('pwd').stdout.gsub("\n", '')
                line = curr_work_dir if curr_work_dir.start_with?(user_info.home.to_s)
                end
                findings.add(line) unless line.start_with?(user_info.home)
            end
            end
        end
        describe 'Initialization files that include executable search paths that include directories outside their home directories' do
            subject { findings.to_a }
            it { should be_empty }
        end
    end
    control 'V-75573' do
        disable_slow_controls = input('disable_slow_controls')
        non_interactive_shells = input('non_interactive_shells')
        if disable_slow_controls
            describe 'This control consistently takes a long to run and has been disabled using the DISABLE_SLOW_CONTROLS attribute.' do
            skip "This control consistently takes a long to run and has been disabled
            using the DISABLE_SLOW_CONTROLS attribute. You must enable this control for a
            full accredidation for production."
            end
        else
            ignore_shells = non_interactive_shells.join('|')
    
            dotfiles = Set[]
            # If shell is nil we should note that
            bad_users = users.where { shell == nil }.raw_data.map { |user_hash| user_hash[:username] }
            describe 'Specified shell for users in /etc/passwd' do
                it 'should specify a shell' do
                    failure_message = "Users without shells set: #{bad_users.join(', ')}"
                    expect(bad_users).to be_empty, failure_message
                end
            end
            u = users.where { (shell != nil && !shell.match(ignore_shells)) && (uid >= 1000 || uid == 0) }.entries
                u.each do |user|
                dotfiles += command("find #{user.home} -xdev -maxdepth 2 -name '.*' ! -name \".bash_history\" -type f").stdout.split("\n")
            end
            ww_files = Set[]
            ww_files = command('find / -perm -002 -type f -exec ls {} \;').stdout.lines
            findings = Set[]
            dotfiles.each do |dotfile|
                dotfile = dotfile.strip
                ww_files.each do |ww_file|
                    ww_file = ww_file.strip
                    count = command("grep -c \"#{ww_file}\" \"#{dotfile}\"").stdout.strip.to_i
                    findings << dotfile if count > 0
                end
            end
            describe 'Local initialization files that are found to reference world-writable files' do
                subject { findings.to_a }
                it { should be_empty }
            end
        end
    end
    control 'V-75587' do
        non_interactive_shells = input('non_interactive_shells')
        exempt_home_users = input('exempt_home_users')
        ignore_shells = non_interactive_shells.join('|')
        
        # If shell is nil we should note that
        bad_users = users.where { shell == nil }.raw_data.map { |user_hash| user_hash[:username] }
        describe 'Specified shell for users in /etc/passwd' do
            it 'should specify a shell' do
                failure_message = "Users without shells set: #{bad_users.join(', ')}"
                expect(bad_users).to be_empty, failure_message
            end
        end
        users.where { (shell != nil && !shell.match(ignore_shells)) && (uid >= 1000) }.entries.each do |user_info|
            next if exempt_home_users.include?(user_info.username.to_s)
    
            home_mount = command(%(df #{user_info.home} --output=target | tail -1)).stdout.strip
            describe user_info.username do
                context 'with mountpoint' do
                    context home_mount do
                    it { should_not be_empty }
                    it { should_not match(%r{^/$}) }
                    end
                end
            end
        end
    end
    control 'V-75603' do
	# Adding alternative syslog file
        syslog_file = file('/var/log/syslog').exist? ? '/var/log/syslog' : '/var/log/messages'

        if !file(syslog_file).exist?
            describe 'Manual test' do
    	        skip 'This control must be reviewed manually, as the syslog file cannot be found'
            end
        else
            describe file(syslog_file) do
                it { should_not be_more_permissive_than('0640') }
  	    end
        end
    end  
    control 'V-75689' do
        describe package('auditd') do
            it { should be_installed }
        end
        if package('auditd').installed?
            if os.arch == 'x86_64'
                describe auditd.syscall('execve').where { arch == 'b64' } do
                    its('action.uniq') { should eq ['always'] }
                    its('list.uniq') { should eq ['exit'] }
                end
            end
            describe auditd.syscall('execve').where { arch == 'b32' } do
                its('action.uniq') { should eq ['always'] }
                its('list.uniq') { should eq ['exit'] }
            end
        end
    end
    control 'V-75809' do
        ufw_status = command('ufw status').stdout.strip.lines.first
        value = ufw_status != nil ? ufw_status.split(':')[1].strip : 'not installed'
    
        describe 'UFW status' do
            subject { value }
            it { should cmp 'active' }
        end
        describe 'Status listings for any allowed services, ports, or applications must be documented with the organization' do
            skip 'Status listings checks must be preformed manually'
        end
    end
    control 'V-75811' do
        lines = command('find / -xdev -type d  \( -perm -0002 -a ! -perm -1000 \) -print 2>/dev/null').stdout.lines
  	if lines.count > 0
    	    lines.each do |line|
      	        dir = line.strip
                if !directory(dir).mode
      	            describe command("ls -ld #{dir} | cut -d ' ' -f 1 | grep t ").stdout.strip do
        	        it { should_not be_empty }
      	            end
                else
		    describe directory(dir) do
        	        it { should be_sticky }
      		    end
		end
    	    end
  	else
    	    describe 'Sticky bit has been set on all world writable directories' do
                subject { lines }
                its('count') { should eq 0 }
            end
        end
    end
    control 'V-75597' do
        if !directory('/var/log').mode or !directory('/var/log').exist?
            describe 'Manual test' do
    	        skip 'This control must be reviewed manually'
            end
        else
            describe directory('/var/log') do
                it { should_not be_more_permissive_than('0770') }
  	    end
        end
    end
    control 'V-75603' do
    	describe 'Manual test' do
    	    skip 'This control must be reviewed manually'
        end
    end
    control 'V-75855' do
        ufw_status_output = command('ufw status').stdout.strip
        is_ufw_active = ufw_status_output != "" ? !ufw_status_output.lines.first.include?('inactive') : false
    
        if is_ufw_active
            describe ufw_status_output do
              it { should match /(LIMIT)/ }
            end
        else
            describe 'UFW status is active' do
              subject { is_ufw_active }
              it { should be true }
            end
        end
    end
    control 'V-75891' do
	is_postfix_installed = package('postfix').installed?
	if is_postfix_installed
            postconf_command = command('postconf -n smtpd_client_restrictions')
	    postconf_output = postconf_command.stdout.strip
	    if !postconf_output.empty?
                smtpd_relay_restrictions = postconf_output.split(' = ')[1].split(', ')
		describe smtpd_relay_restrictions do
		    it { should be_in %w[permit_mynetworks permit_sasl_authenticated reject] }
		end
	    else
		describe 'Postfix smtpd command output' do
		    it 'should describe the smtpd client restrictions' do
			failure_message = "Postfix smtpd command output was empty, error: #{postconf_command.stderr}"
			expect(postconf_output.empty?).to cmp false, failure_message
		    end
		end
	    end
	else
	    impact 0.0
	    describe 'Control Not Applicable as postfix is not installed' do
	        subject { is_postfix_installed }
	        it { should be false }
	    end
	end    
    end
    control 'V-75389' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75393' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75435' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75439' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75441' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75443' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75445' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75469' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75485' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75489' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75491' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75525' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75527' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75529' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75537' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75605' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75607' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75609' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75611' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75613' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75615' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75617' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75621' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75623' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75625' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75627' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75629' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75631' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75633' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75635' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75637' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75639' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75641' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75643' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75645' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75647' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75653' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75655' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75657' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75659' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75661' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75663' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75665' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75667' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75687' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75691' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75693' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75695' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75697' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75699' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75707' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75709' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75711' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75713' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75715' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75717' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75719' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75721' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75723' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75725' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75727' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75729' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75731' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75733' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75735' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75737' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75739' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75741' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75743' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75745' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75747' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75749' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75751' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75753' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75755' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75757' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75759' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75761' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75765' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75767' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75769' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75771' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75773' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75775' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75777' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75779' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75781' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75783' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75785' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75787' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75789' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75791' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75793' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75795' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75803' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75807' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75813' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75815' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75817' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75819' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75821' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75823' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75825' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75829' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75831' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75837' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75859' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75863' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75869' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75897' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75903' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75905' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75907' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75909' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-75911' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-78005' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-78007' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-80961' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-80965' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
    control 'V-80969' do
        impact 0.0
        desc 'caveat', 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        describe 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy' do
            skip 'This is Not Applicable since the related security control is not included in ***SPONSOR*** policy'
        end
    end
end
