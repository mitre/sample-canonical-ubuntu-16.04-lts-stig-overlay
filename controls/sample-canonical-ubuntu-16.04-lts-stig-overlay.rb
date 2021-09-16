
include_controls 'canonical-ubuntu-16.04-lts-stig-baseline' do
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
    control 'V-75689' do
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
        else
            describe package('auditd') do
                it { should be_installed }
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

    control 'V-75621' do
        # TEST-WIP
        log_file_path = input('log_file_path')
        log_file_dir = input('log_file_dir')

        if directory(log_file_dir).exist?
            available_storage = filesystem(log_file_dir).free_kb
            log_file_size = file(log_file_path).size
            standard_audit_log_size = input('standard_audit_log_size')
        
            describe ('Current audit log file size is less than the specified standard of ' + standard_audit_log_size.to_s) do
                subject { log_file_size.to_i }
                it { should be <= standard_audit_log_size }
            end
            describe ('Available storage for audit log should be more than the defined standard of ' + standard_audit_log_size.to_s) do
                subject { available_storage.to_i }
                it { should be > standard_audit_log_size }
            end
        else
            it 'should have a log directory and file that exist' do
                dir_failure_message = "Audit directory: #{log_file_dir} does not exist"
                expect(directory(log_file_dir)).to exist, dir_failure_message
            end
            it 'should have a log file that exists' do
                path_failure_message = "Audit path: #{log_file_path} does not exist"
                expect(file(log_file_path)).to exist, path_failure_message
            end
        end
    end

    control 'V-75623' do
        # TEST-WIP
        if package('auditd').installed?
            space_left_action = auditd_conf.space_left_action
            if space_left_action.casecmp?('email')
                action_mail_acct = input('action_mail_acct')
                describe auditd_conf do
                    its('action_mail_acct') { should cmp action_mail_acct }
                end
            elsif space_left_action.casecmp?('syslog') || space_left_action.casecmp?('exec')
                describe.one do
                    describe auditd_conf do
                        its('space_left_action') { should cmp 'syslog' }
                    end
                    describe auditd_conf do
                        its('space_left_action') { should cmp 'exec' }
                    end
                end
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end
    control 'V-75625' do
        # TEST-WIP
        security_accounts = input('security_accounts').join('|')
        if package('auditd').installed?
            space_left_action = auditd_conf.space_left_action

            describe 'System Administrator (SA) and Information System Security Officer (ISSO) are notified in the event of an audit processing failure' do
                subject { security_accounts.include?(space_left_action) }
                it { should be true }
            end 
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end

    control 'V-75635' do
        # TEST-WIP
        if package('auditd').installed?
            log_file = auditd_conf.log_file
            log_file_exists = !log_file.nil?
            if log_file_exists
                describe file(log_file) do
                    it { should_not be_more_permissive_than('0600') }
                end
            else
                describe ('Audit log file ' + log_file + ' exists') do
                    subject { log_file_exists }
                    it { should be true }
                end
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end

    control 'V-75661' do
        # TEST-WIP
        @audit_file = '/etc/passwd'

        if package('auditd').installed?
            audit_lines_exist = !auditd.lines.index { |line| line.include?(@audit_file) }.nil?
            if audit_lines_exist
                describe auditd.file(@audit_file) do
                    its('permissions') { should_not cmp [] }
                    its('action') { should_not include 'never' }
                end

                @perms = auditd.file(@audit_file).permissions

                @perms.each do |perm|
                    describe perm do
                        it { should include 'w' }
                        it { should include 'a' }
                    end
                end
            else
                describe ('Audit line(s) for ' + @audit_file + ' exist') do
                    subject { audit_lines_exist }
                    it { should be true }
                end
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end

    control 'V-75663' do
        # TEST-WIP
        @audit_file = '/etc/group'
        if package('auditd').installed?
            audit_lines_exist = !auditd.lines.index { |line| line.include?(@audit_file) }.nil?
            if audit_lines_exist
                describe auditd.file(@audit_file) do
                    its('permissions') { should_not cmp [] }
                    its('action') { should_not include 'never' }
                end

                @perms = auditd.file(@audit_file).permissions

                @perms.each do |perm|
                    describe perm do
                        it { should include 'w' }
                        it { should include 'a' }
                    end
                end
            else
                describe ('Audit line(s) for ' + @audit_file + ' exist') do
                    subject { audit_lines_exist }
                    it { should be true }
                end
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end

    control 'V-75665' do
        # TEST-WIP
        @audit_file = '/etc/gshadow'
        if package('auditd').installed?
            audit_lines_exist = !auditd.lines.index { |line| line.include?(@audit_file) }.nil?
            if audit_lines_exist
                describe auditd.file(@audit_file) do
                    its('permissions') { should_not cmp [] }
                    its('action') { should_not include 'never' }
                end

                @perms = auditd.file(@audit_file).permissions

                @perms.each do |perm|
                    describe perm do
                        it { should include 'w' }
                        it { should include 'a' }
                    end
                end
            else
                describe ('Audit line(s) for ' + @audit_file + ' exist') do
                    subject { audit_lines_exist }
                    it { should be true }
                end
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end

    control 'V-75667' do
        # TEST-WIP
        @audit_file = '/etc/shadow'
        if package('auditd').installed?
            audit_lines_exist = !auditd.lines.index { |line| line.include?(@audit_file) }.nil?
            if audit_lines_exist
                describe auditd.file(@audit_file) do
                    its('permissions') { should_not cmp [] }
                    its('action') { should_not include 'never' }
                end

                @perms = auditd.file(@audit_file).permissions

                @perms.each do |perm|
                    describe perm do
                        it { should include 'w' }
                        it { should include 'a' }
                    end
                end
            else
                describe ('Audit line(s) for ' + @audit_file + ' exist') do
                    subject { audit_lines_exist }
                    it { should be true }
                end
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end

    control 'V-75687' do
        # TEST-WIP
        @audit_file = '/etc/security/opasswd'
        if package('auditd').installed? and file(@audit_file).exist?
            audit_lines_exist = !auditd.lines.index { |line| line.include?(@audit_file) }.nil?
            if audit_lines_exist
                describe auditd.file(@audit_file) do
                    its('permissions') { should_not cmp [] }
                    its('action') { should_not include 'never' }
                end

                @perms = auditd.file(@audit_file).permissions

                @perms.each do |perm|
                    describe perm do
                        it { should include 'w' }
                        it { should include 'a' }
                    end
                end
            else
                describe ('Audit line(s) for ' + @audit_file + ' exist') do
                    subject { audit_lines_exist }
                    it { should be true }
                end
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
            it 'should have /etc/security/opasswd installed' do
                failure_message = "/etc/security/opasswd is not present"
                expect(file(@audit_file)).to exist, failure_message
            end
        end
    end

    control 'V-75691' do
        # TEST-WIP
        @audit_file = '/bin/su'
        if package('auditd').installed?
            audit_lines_exist = !auditd.lines.index { |line| line.include?(@audit_file) }.nil?
            if audit_lines_exist
                describe auditd.file(@audit_file) do
                    its('permissions') { should_not cmp [] }
                    its('action') { should_not include 'never' }
                    its('action.uniq') { should eq ['always'] }
                    its('list.uniq') { should eq ['exit'] }
                end

                @perms = auditd.file(@audit_file).permissions

                @perms.each do |perm|
                    describe perm do
                        it { should include 'x' }
                    end
                end
            else
                describe ('Audit line(s) for ' + @audit_file + ' exist') do
                    subject { audit_lines_exist }
                    it { should be true }
                end
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end

    control 'V-75693' do
        # TEST-WIP
        @audit_file = '/usr/bin/chfn'
        if package('auditd').installed?
            audit_lines_exist = !auditd.lines.index { |line| line.include?(@audit_file) }.nil?
            if audit_lines_exist
                describe auditd.file(@audit_file) do
                    its('permissions') { should_not cmp [] }
                    its('action') { should_not include 'never' }
                    its('action.uniq') { should eq ['always'] }
                    its('list.uniq') { should eq ['exit'] }
                end

                @perms = auditd.file(@audit_file).permissions

                @perms.each do |perm|
                    describe perm do
                        it { should include 'x' }
                    end
                end
            else
                describe ('Audit line(s) for ' + @audit_file + ' exist') do
                    subject { audit_lines_exist }
                    it { should be true }
                end
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end

    control 'V-75695' do
        # TEST-WIP
        @audit_file = '/bin/mount'
        if package('auditd').installed?
            audit_lines_exist = !auditd.lines.index { |line| line.include?(@audit_file) }.nil?
            if audit_lines_exist
                describe auditd.file(@audit_file) do
                    its('permissions') { should_not cmp [] }
                    its('action') { should_not include 'never' }
                    its('action.uniq') { should eq ['always'] }
                    its('list.uniq') { should eq ['exit'] }
                end

                @perms = auditd.file(@audit_file).permissions

                @perms.each do |perm|
                    describe perm do
                        it { should include 'x' }
                    end
                end
            else
                describe ('Audit line(s) for ' + @audit_file + ' exist') do
                    subject { audit_lines_exist }
                    it { should be true }
                end
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end 
    end

    control 'V-75697' do
        # TEST-WIP
        @audit_file = '/bin/umount'
        if package('auditd').installed?
            audit_lines_exist = !auditd.lines.index { |line| line.include?(@audit_file) }.nil?
            if audit_lines_exist
                describe auditd.file(@audit_file) do
                    its('permissions') { should_not cmp [] }
                    its('action') { should_not include 'never' }
                    its('action.uniq') { should eq ['always'] }
                    its('list.uniq') { should eq ['exit'] }
                end

                @perms = auditd.file(@audit_file).permissions

                @perms.each do |perm|
                    describe perm do
                        it { should include 'x' }
                    end
                end
            else
                describe ('Audit line(s) for ' + @audit_file + ' exist') do
                    subject { audit_lines_exist }
                    it { should be true }
                end
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end

    control 'V-75699' do
        # TEST-WIP
        @audit_file = '/usr/bin/ssh-agent'
        if package('auditd').installed?
            audit_lines_exist = !auditd.lines.index { |line| line.include?(@audit_file) }.nil?
            if audit_lines_exist
                describe auditd.file(@audit_file) do
                    its('permissions') { should_not cmp [] }
                    its('action') { should_not include 'never' }
                    its('action.uniq') { should eq ['always'] }
                    its('list.uniq') { should eq ['exit'] }
                end

                @perms = auditd.file(@audit_file).permissions

                @perms.each do |perm|
                    describe perm do
                        it { should include 'x' }
                    end
                end
            else
                describe ('Audit line(s) for ' + @audit_file + ' exist') do
                    subject { audit_lines_exist }
                    it { should be true }
                end
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end

    control 'V-75707' do
        # TEST-WIP
        @audit_file = '/usr/lib/openssh/ssh-keysign'
        if package('auditd').installed?
            
            audit_lines_exist = !auditd.lines.index { |line| line.include?(@audit_file) }.nil?
            if audit_lines_exist
                describe auditd.file(@audit_file) do
                    its('permissions') { should_not cmp [] }
                    its('action') { should_not include 'never' }
                    its('action.uniq') { should eq ['always'] }
                    its('list.uniq') { should eq ['exit'] }
                end
                
                @perms = auditd.file(@audit_file).permissions
                
                @perms.each do |perm|
                    describe perm do
                        it { should include 'x' }
                    end
                end
            else
                describe ('Audit line(s) for ' + @audit_file + ' exist') do
                    subject { audit_lines_exist }
                    it { should be true }
                end
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end

    control 'V-75709' do
        # TEST-WIP
        @audit_file = '/sbin/insmod'
        if package('auditd').installed?
            audit_lines_exist = !auditd.lines.index { |line| line.include?(@audit_file) }.nil?
            if audit_lines_exist
                describe auditd.file(@audit_file) do
                    its('permissions') { should_not cmp [] }
                    its('action') { should_not include 'never' }
                end

                @perms = auditd.file(@audit_file).permissions

                @perms.each do |perm|
                    describe perm do
                        it { should include 'x' }
                    end
                end
            else
                describe ('Audit line(s) for ' + @audit_file + ' exist') do
                    subject { audit_lines_exist }
                    it { should be true }
                end
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end

    control 'V-75711' do
        # TEST-WIP
        @audit_file = '/sbin/rmmod'
        if package('auditd').installed?

            audit_lines_exist = !auditd.lines.index { |line| line.include?(@audit_file) }.nil?
            if audit_lines_exist
                describe auditd.file(@audit_file) do
                    its('permissions') { should_not cmp [] }
                    its('action') { should_not include 'never' }
                end

                @perms = auditd.file(@audit_file).permissions

                @perms.each do |perm|
                    describe perm do
                        it { should include 'x' }
                    end
                end
            else
                describe ('Audit line(s) for ' + @audit_file + ' exist') do
                    subject { audit_lines_exist }
                    it { should be true }
                end
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end

    control 'V-75713' do
        # TEST-WIP
        @audit_file = '/sbin/modprobe'
        if package('auditd').installed?

            audit_lines_exist = !auditd.lines.index { |line| line.include?(@audit_file) }.nil?
            if audit_lines_exist
                describe auditd.file(@audit_file) do
                    its('permissions') { should_not cmp [] }
                    its('action') { should_not include 'never' }
                end

                @perms = auditd.file(@audit_file).permissions

                @perms.each do |perm|
                    describe perm do
                        it { should include 'x' }
                    end
                end
            else
                describe ('Audit line(s) for ' + @audit_file + ' exist') do
                    subject { audit_lines_exist }
                    it { should be true }
                end
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end

    control 'V-75715' do
        # TEST-WIP
        @audit_file = '/bin/kmod'
        if package('auditd').installed?

            audit_lines_exist = !auditd.lines.index { |line| line.include?(@audit_file) }.nil?
            if audit_lines_exist
                describe auditd.file(@audit_file) do
                    its('permissions') { should_not cmp [] }
                    its('action') { should_not include 'never' }
                end

                @perms = auditd.file(@audit_file).permissions

                @perms.each do |perm|
                    describe perm do
                        it { should include 'x' }
                    end
                end
            else
                describe ('Audit line(s) for ' + @audit_file + ' exist') do
                    subject { audit_lines_exist }
                    it { should be true }
                end
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end

    control 'V-75717' do
        # TEST-WIP
        if package('auditd').installed?
            if os.arch == 'x86_64'
                describe auditd.syscall('setxattr').where { arch == 'b64' } do
                    its('action.uniq') { should eq ['always'] }
                    its('list.uniq') { should eq ['exit'] }
                end
            end
            describe auditd.syscall('setxattr').where { arch == 'b32' } do
                its('action.uniq') { should eq ['always'] }
                its('list.uniq') { should eq ['exit'] }
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end

    control 'V-75719' do
        # TEST-WIP
        if package('auditd').installed?
            if os.arch == 'x86_64'
                describe auditd.syscall('lsetxattr').where { arch == 'b64' } do
                    its('action.uniq') { should eq ['always'] }
                    its('list.uniq') { should eq ['exit'] }
                end
            end
            describe auditd.syscall('lsetxattr').where { arch == 'b32' } do
                its('action.uniq') { should eq ['always'] }
                its('list.uniq') { should eq ['exit'] }
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end

    control 'V-75721' do
        # TEST-WIP
        if package('auditd').installed?
            if os.arch == 'x86_64'
                describe auditd.syscall('fsetxattr').where { arch == 'b64' } do
                    its('action.uniq') { should eq ['always'] }
                    its('list.uniq') { should eq ['exit'] }
                end
            end
            describe auditd.syscall('fsetxattr').where { arch == 'b32' } do
                its('action.uniq') { should eq ['always'] }
                its('list.uniq') { should eq ['exit'] }
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end

    control 'V-75723' do
        # TEST-WIP
        if package('auditd').installed?
            if os.arch == 'x86_64'
                describe auditd.syscall('removexattr').where { arch == 'b64' } do
                    its('action.uniq') { should eq ['always'] }
                    its('list.uniq') { should eq ['exit'] }
                end
            end
            describe auditd.syscall('removexattr').where { arch == 'b32' } do
                its('action.uniq') { should eq ['always'] }
                its('list.uniq') { should eq ['exit'] }
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
        
    end

    control 'V-75725' do
        # TEST-WIP
        if package('auditd').installed?
            if os.arch == 'x86_64'
                describe auditd.syscall('lremovexattr').where { arch == 'b64' } do
                    its('action.uniq') { should eq ['always'] }
                    its('list.uniq') { should eq ['exit'] }
                end
            end
            describe auditd.syscall('lremovexattr').where { arch == 'b32' } do
                its('action.uniq') { should eq ['always'] }
                its('list.uniq') { should eq ['exit'] }
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end

    control 'V-75727' do
        # TEST-WIP
        if package('auditd').installed?
            if os.arch == 'x86_64'
                describe auditd.syscall('fremovexattr').where { arch == 'b64' } do
                    its('action.uniq') { should eq ['always'] }
                    its('list.uniq') { should eq ['exit'] }
                end
            end
            describe auditd.syscall('fremovexattr').where { arch == 'b32' } do
                its('action.uniq') { should eq ['always'] }
                its('list.uniq') { should eq ['exit'] }
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end

    control 'V-75729' do
        # TEST-WIP
        if package('auditd').installed?
            if os.arch == 'x86_64'
                describe auditd.syscall('chown').where { arch == 'b64' } do
                    its('action.uniq') { should eq ['always'] }
                    its('list.uniq') { should eq ['exit'] }
                end
            end
            describe auditd.syscall('chown').where { arch == 'b32' } do
                its('action.uniq') { should eq ['always'] }
                its('list.uniq') { should eq ['exit'] }
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end

    control 'V-75731' do
        # TEST-WIP
        if package('auditd').installed?
            if os.arch == 'x86_64'
                describe auditd.syscall('fchown').where { arch == 'b64' } do
                    its('action.uniq') { should eq ['always'] }
                    its('list.uniq') { should eq ['exit'] }
                end
            end
            describe auditd.syscall('fchown').where { arch == 'b32' } do
                its('action.uniq') { should eq ['always'] }
                its('list.uniq') { should eq ['exit'] }
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end

    control 'V-75733' do
        # TEST-WIP
        if package('auditd').installed?
            if os.arch == 'x86_64'
                describe auditd.syscall('fchownat').where { arch == 'b64' } do
                    its('action.uniq') { should eq ['always'] }
                    its('list.uniq') { should eq ['exit'] }
                end
            end
            describe auditd.syscall('fchownat').where { arch == 'b32' } do
                its('action.uniq') { should eq ['always'] }
                its('list.uniq') { should eq ['exit'] }
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end

    control 'V-75735' do
        # TEST-WIP
        if package('auditd').installed?
            if os.arch == 'x86_64'
                describe auditd.syscall('lchown').where { arch == 'b64' } do
                    its('action.uniq') { should eq ['always'] }
                    its('list.uniq') { should eq ['exit'] }
                end
            end
            describe auditd.syscall('lchown').where { arch == 'b32' } do
                its('action.uniq') { should eq ['always'] }
                its('list.uniq') { should eq ['exit'] }
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end

    control 'V-75737' do
        # TEST-WIP
        if package('auditd').installed?
            if os.arch == 'x86_64'
                describe auditd.syscall('chmod').where { arch == 'b64' } do
                    its('action.uniq') { should eq ['always'] }
                    its('list.uniq') { should eq ['exit'] }
                end
            end
            describe auditd.syscall('chmod').where { arch == 'b32' } do
                its('action.uniq') { should eq ['always'] }
                its('list.uniq') { should eq ['exit'] }
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end

    control 'V-75739' do
        # TEST-WIP
        if package('auditd').installed?
            if os.arch == 'x86_64'
                describe auditd.syscall('fchmod').where { arch == 'b64' } do
                    its('action.uniq') { should eq ['always'] }
                    its('list.uniq') { should eq ['exit'] }
                end
            end
            describe auditd.syscall('fchmod').where { arch == 'b32' } do
                its('action.uniq') { should eq ['always'] }
                its('list.uniq') { should eq ['exit'] }
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end

    control 'V-75741' do
        # TEST-WIP
        if package('auditd').installed?
            if os.arch == 'x86_64'
                describe auditd.syscall('fchmodat').where { arch == 'b64' } do
                    its('action.uniq') { should eq ['always'] }
                    its('list.uniq') { should eq ['exit'] }
                end
            end
            describe auditd.syscall('fchmodat').where { arch == 'b32' } do
                its('action.uniq') { should eq ['always'] }
                its('list.uniq') { should eq ['exit'] }
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end

    control 'V-75743' do
        # TEST-WIP
        if package('auditd').installed?
            if os.arch == 'x86_64'
                describe auditd.syscall('open').where { arch == 'b64' } do
                    its('action.uniq') { should eq ['always'] }
                    its('list.uniq') { should eq ['exit'] }
                    its('exit.uniq') { should include '-EPERM' }
                end
                describe auditd.syscall('open').where { arch == 'b64' } do
                    its('action.uniq') { should eq ['always'] }
                    its('list.uniq') { should eq ['exit'] }
                    its('exit.uniq') { should include '-EACCES' }
                end
            end
            describe auditd.syscall('open').where { arch == 'b32' } do
                its('action.uniq') { should eq ['always'] }
                its('list.uniq') { should eq ['exit'] }
                its('exit.uniq') { should include '-EPERM' }
            end
            describe auditd.syscall('open').where { arch == 'b32' } do
                its('action.uniq') { should eq ['always'] }
                its('list.uniq') { should eq ['exit'] }
                its('exit.uniq') { should include '-EACCES' }
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end

    control 'V-75745' do
        # TEST-WIP
        if package('auditd').installed?
            if os.arch == 'x86_64'
                describe auditd.syscall('truncate').where { arch == 'b64' } do
                    its('action.uniq') { should eq ['always'] }
                    its('list.uniq') { should eq ['exit'] }
                    its('exit.uniq') { should include '-EPERM' }
                end
                describe auditd.syscall('truncate').where { arch == 'b64' } do
                    its('action.uniq') { should eq ['always'] }
                    its('list.uniq') { should eq ['exit'] }
                    its('exit.uniq') { should include '-EACCES' }
                end
            end
            describe auditd.syscall('truncate').where { arch == 'b32' } do
                its('action.uniq') { should eq ['always'] }
                its('list.uniq') { should eq ['exit'] }
                its('exit.uniq') { should include '-EPERM' }
            end
            describe auditd.syscall('truncate').where { arch == 'b32' } do
                its('action.uniq') { should eq ['always'] }
                its('list.uniq') { should eq ['exit'] }
                its('exit.uniq') { should include '-EACCES' }
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end

    control 'V-75747' do
        # TEST-WIP
        if package('auditd').installed?
            if os.arch == 'x86_64'
                describe auditd.syscall('ftruncate').where { arch == 'b64' } do
                    its('action.uniq') { should eq ['always'] }
                    its('list.uniq') { should eq ['exit'] }
                    its('exit.uniq') { should include '-EPERM' }
                end
                describe auditd.syscall('ftruncate').where { arch == 'b64' } do
                    its('action.uniq') { should eq ['always'] }
                    its('list.uniq') { should eq ['exit'] }
                    its('exit.uniq') { should include '-EACCES' }
                end
            end
            describe auditd.syscall('ftruncate').where { arch == 'b32' } do
                its('action.uniq') { should eq ['always'] }
                its('list.uniq') { should eq ['exit'] }
                its('exit.uniq') { should include '-EPERM' }
            end
            describe auditd.syscall('ftruncate').where { arch == 'b32' } do
                its('action.uniq') { should eq ['always'] }
                its('list.uniq') { should eq ['exit'] }
                its('exit.uniq') { should include '-EACCES' }
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end

    control 'V-75749' do
        # TEST-WIP
        if package('auditd').installed?
            if os.arch == 'x86_64'
                describe auditd.syscall('creat').where { arch == 'b64' } do
                    its('action.uniq') { should eq ['always'] }
                    its('list.uniq') { should eq ['exit'] }
                    its('exit.uniq') { should include '-EPERM' }
                end
                describe auditd.syscall('creat').where { arch == 'b64' } do
                    its('action.uniq') { should eq ['always'] }
                    its('list.uniq') { should eq ['exit'] }
                    its('exit.uniq') { should include '-EACCES' }
                end
            end
            describe auditd.syscall('creat').where { arch == 'b32' } do
                its('action.uniq') { should eq ['always'] }
                its('list.uniq') { should eq ['exit'] }
                its('exit.uniq') { should include '-EPERM' }
            end
            describe auditd.syscall('creat').where { arch == 'b32' } do
                its('action.uniq') { should eq ['always'] }
                its('list.uniq') { should eq ['exit'] }
                its('exit.uniq') { should include '-EACCES' }
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end

    control 'V-75751' do
        # TEST-WIP
        if package('auditd').installed?
            if os.arch == 'x86_64'
                describe auditd.syscall('openat').where { arch == 'b64' } do
                    its('action.uniq') { should eq ['always'] }
                    its('list.uniq') { should eq ['exit'] }
                    its('exit.uniq') { should include '-EPERM' }
                end
                describe auditd.syscall('openat').where { arch == 'b64' } do
                    its('action.uniq') { should eq ['always'] }
                    its('list.uniq') { should eq ['exit'] }
                    its('exit.uniq') { should include '-EACCES' }
                end
            end
            describe auditd.syscall('openat').where { arch == 'b32' } do
                its('action.uniq') { should eq ['always'] }
                its('list.uniq') { should eq ['exit'] }
                its('exit.uniq') { should include '-EPERM' }
            end
            describe auditd.syscall('openat').where { arch == 'b32' } do
                its('action.uniq') { should eq ['always'] }
                its('list.uniq') { should eq ['exit'] }
                its('exit.uniq') { should include '-EACCES' }
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end

    control 'V-75753' do
        # TEST-WIP
        if package('auditd').installed?
            if os.arch == 'x86_64'
                describe auditd.syscall('open_by_handle_at').where { arch == 'b64' } do
                    its('action.uniq') { should eq ['always'] }
                    its('list.uniq') { should eq ['exit'] }
                    its('exit.uniq') { should include '-EPERM' }
                end
                describe auditd.syscall('open_by_handle_at').where { arch == 'b64' } do
                    its('action.uniq') { should eq ['always'] }
                    its('list.uniq') { should eq ['exit'] }
                    its('exit.uniq') { should include '-EACCES' }
                end
            end
            describe auditd.syscall('open_by_handle_at').where { arch == 'b32' } do
                its('action.uniq') { should eq ['always'] }
                its('list.uniq') { should eq ['exit'] }
                its('exit.uniq') { should include '-EPERM' }
            end
            describe auditd.syscall('open_by_handle_at').where { arch == 'b32' } do
                its('action.uniq') { should eq ['always'] }
                its('list.uniq') { should eq ['exit'] }
                its('exit.uniq') { should include '-EACCES' }
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end

    control 'V-75755' do
        # TEST-WIP
        @audit_file = '/usr/bin/sudo'
        if package('auditd').installed?
            audit_lines_exist = !auditd.lines.index { |line| line.include?(@audit_file) }.nil?
            if audit_lines_exist
                describe auditd.file(@audit_file) do
                    its('permissions') { should_not cmp [] }
                    its('action') { should_not include 'never' }
                end

                @perms = auditd.file(@audit_file).permissions

                @perms.each do |perm|
                    describe perm do
                        it { should include 'x' }
                    end
                end
            else
                describe ('Audit line(s) for ' + @audit_file + ' exist') do
                    subject { audit_lines_exist }
                    it { should be true }
                end
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end

    control 'V-75757' do
        # TEST-WIP
        @audit_file = '/usr/bin/sudoedit'
        if package('auditd').installed?

            audit_lines_exist = !auditd.lines.index { |line| line.include?(@audit_file) }.nil?
            if audit_lines_exist
                describe auditd.file(@audit_file) do
                    its('permissions') { should_not cmp [] }
                    its('action') { should_not include 'never' }
                end

                @perms = auditd.file(@audit_file).permissions

                @perms.each do |perm|
                    describe perm do
                        it { should include 'x' }
                    end
                end

            else
                describe ('Audit line(s) for ' + @audit_file + ' exist') do
                    subject { audit_lines_exist }
                    it { should be true }
                end
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end

    control 'V-75759' do
        # TEST-WIP
        @audit_file = '/usr/bin/chsh'
        if package('auditd').installed?

            audit_lines_exist = !auditd.lines.index { |line| line.include?(@audit_file) }.nil?
            if audit_lines_exist
                describe auditd.file(@audit_file) do
                    its('permissions') { should_not cmp [] }
                    its('action') { should_not include 'never' }
                end

                @perms = auditd.file(@audit_file).permissions

                @perms.each do |perm|
                    describe perm do
                        it { should include 'x' }
                    end
                end
            else
                describe ('Audit line(s) for ' + @audit_file + ' exist') do
                    subject { audit_lines_exist }
                    it { should be true }
                end
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end

    control 'V-75761' do
        # TEST-WIP
        @audit_file = '/usr/bin/newgrp'
        if package('auditd').installed?

            audit_lines_exist = !auditd.lines.index { |line| line.include?(@audit_file) }.nil?
            if audit_lines_exist
                describe auditd.file(@audit_file) do
                    its('permissions') { should_not cmp [] }
                    its('action') { should_not include 'never' }
                end

                @perms = auditd.file(@audit_file).permissions

                @perms.each do |perm|
                    describe perm do
                        it { should include 'x' }
                    end
                end
            else
                describe ('Audit line(s) for ' + @audit_file + ' exist') do
                    subject { audit_lines_exist }
                    it { should be true }
                end
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end

    control 'V-75765' do
        # TEST-WIP
        @audit_file = '/sbin/apparmor_parser'
        if package('auditd').installed?

            audit_lines_exist = !auditd.lines.index { |line| line.include?(@audit_file) }.nil?
            if audit_lines_exist
                describe auditd.file(@audit_file) do
                    its('permissions') { should_not cmp [] }
                    its('action') { should_not include 'never' }
                end

                @perms = auditd.file(@audit_file).permissions

                @perms.each do |perm|
                    describe perm do
                        it { should include 'x' }
                    end
                end
            else
                describe ('Audit line(s) for ' + @audit_file + ' exist') do
                    subject { audit_lines_exist }
                    it { should be true }
                end
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end

    control 'V-75767' do
        # TEST-WIP
        @audit_file = '/usr/bin/setfacl'
        if package('auditd').installed?

        audit_lines_exist = !auditd.lines.index { |line| line.include?(@audit_file) }.nil?
        if audit_lines_exist
            describe auditd.file(@audit_file) do
                its('permissions') { should_not cmp [] }
                its('action') { should_not include 'never' }
            end

            @perms = auditd.file(@audit_file).permissions

            @perms.each do |perm|
                describe perm do
                    it { should include 'x' }
                end
            end
        else
            describe ('Audit line(s) for ' + @audit_file + ' exist') do
                subject { audit_lines_exist }
                it { should be true }
            end
        end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end

    control 'V-75769' do
        # TEST-WIP
        @audit_file = '/usr/bin/chacl'
        if package('auditd').installed?

        audit_lines_exist = !auditd.lines.index { |line| line.include?(@audit_file) }.nil?
        if audit_lines_exist
            describe auditd.file(@audit_file) do
                its('permissions') { should_not cmp [] }
                its('action') { should_not include 'never' }
            end

            @perms = auditd.file(@audit_file).permissions

            @perms.each do |perm|
                describe perm do
                    it { should include 'x' }
                end
            end
        else
            describe ('Audit line(s) for ' + @audit_file + ' exist') do
                subject { audit_lines_exist }
                it { should be true }
            end
        end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end

    control 'V-75771' do
        # TEST-WIP
        @audit_file = '/var/log/tallylog'
        if package('auditd').installed?

            audit_lines_exist = !auditd.lines.index { |line| line.include?(@audit_file) }.nil?
            if audit_lines_exist
                describe auditd.file(@audit_file) do
                    its('permissions') { should_not cmp [] }
                    its('action') { should_not include 'never' }
                end

                @perms = auditd.file(@audit_file).permissions

                @perms.each do |perm|
                    describe perm do
                        it { should include 'w' }
                        it { should include 'a' }
                    end
                end
            else
                describe ('Audit line(s) for ' + @audit_file + ' exist') do
                    subject { audit_lines_exist }
                    it { should be true }
                end
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end

    control 'V-75773' do
        # TEST-WIP
        @audit_file = '/var/log/faillog'
        if package('auditd').installed?

            audit_lines_exist = !auditd.lines.index { |line| line.include?(@audit_file) }.nil?
            if audit_lines_exist
                describe auditd.file(@audit_file) do
                    its('permissions') { should_not cmp [] }
                    its('action') { should_not include 'never' }
                end

                @perms = auditd.file(@audit_file).permissions

                @perms.each do |perm|
                    describe perm do
                        it { should include 'w' }
                        it { should include 'a' }
                    end
                end
            else
                describe ('Audit line(s) for ' + @audit_file + ' exist') do
                    subject { audit_lines_exist }
                    it { should be true }
                end
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end

    control 'V-75775' do
        # TEST-WIP
        @audit_file = '/var/log/lastlog'
        if package('auditd').installed?

            audit_lines_exist = !auditd.lines.index { |line| line.include?(@audit_file) }.nil?
            if audit_lines_exist
                describe auditd.file(@audit_file) do
                    its('permissions') { should_not cmp [] }
                    its('action') { should_not include 'never' }
                end

                @perms = auditd.file(@audit_file).permissions

                @perms.each do |perm|
                    describe perm do
                        it { should include 'w' }
                        it { should include 'a' }
                    end
                end
            else
                describe ('Audit line(s) for ' + @audit_file + ' exist') do
                    subject { audit_lines_exist }
                    it { should be true }
                end
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end

    control 'V-75777' do
        # TEST-WIP
        @audit_file = '/usr/bin/passwd'
        if package('auditd').installed?

            audit_lines_exist = !auditd.lines.index { |line| line.include?(@audit_file) }.nil?
            if audit_lines_exist
                describe auditd.file(@audit_file) do
                    its('permissions') { should_not cmp [] }
                    its('action') { should_not include 'never' }
                end

                @perms = auditd.file(@audit_file).permissions

                @perms.each do |perm|
                    describe perm do
                        it { should include 'x' }
                    end
                end
            else
                describe ('Audit line(s) for ' + @audit_file + ' exist') do
                    subject { audit_lines_exist }
                    it { should be true }
                end
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end

    control 'V-75779' do
        # TEST-WIP
        @audit_file = '/sbin/unix_update'
        if package('auditd').installed?

            audit_lines_exist = !auditd.lines.index { |line| line.include?(@audit_file) }.nil?
            if audit_lines_exist
                describe auditd.file(@audit_file) do
                    its('permissions') { should_not cmp [] }
                    its('action') { should_not include 'never' }
                end

                @perms = auditd.file(@audit_file).permissions

                @perms.each do |perm|
                    describe perm do
                        it { should include 'x' }
                    end
                end
            else
                describe ('Audit line(s) for ' + @audit_file + ' exist') do
                    subject { audit_lines_exist }
                    it { should be true }
                end
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end

    control 'V-75781' do
        # TEST-WIP
        @audit_file = '/usr/bin/gpasswd'
        if package('auditd').installed?

            audit_lines_exist = !auditd.lines.index { |line| line.include?(@audit_file) }.nil?
            if audit_lines_exist
                describe auditd.file(@audit_file) do
                    its('permissions') { should_not cmp [] }
                    its('action') { should_not include 'never' }
                end

                @perms = auditd.file(@audit_file).permissions

                @perms.each do |perm|
                    describe perm do
                        it { should include 'x' }
                    end
                end
            else
                describe ('Audit line(s) for ' + @audit_file + ' exist') do
                    subject { audit_lines_exist }
                    it { should be true }
                end
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end

    control 'V-75783' do
        # TEST-WIP
        @audit_file = '/usr/bin/chage'
        if package('auditd').installed?

            audit_lines_exist = !auditd.lines.index { |line| line.include?(@audit_file) }.nil?
            if audit_lines_exist
                describe auditd.file(@audit_file) do
                    its('permissions') { should_not cmp [] }
                    its('action') { should_not include 'never' }
                end

                @perms = auditd.file(@audit_file).permissions

                @perms.each do |perm|
                    describe perm do
                        it { should include 'x' }
                    end
                end
            else
                describe ('Audit line(s) for ' + @audit_file + ' exist') do
                    subject { audit_lines_exist }
                    it { should be true }
                end
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end

    control 'V-75785' do
        # TEST-WIP
        @audit_file = '/usr/sbin/usermod'
        if package('auditd').installed?

            audit_lines_exist = !auditd.lines.index { |line| line.include?(@audit_file) }.nil?
            if audit_lines_exist
                describe auditd.file(@audit_file) do
                    its('permissions') { should_not cmp [] }
                    its('action') { should_not include 'never' }
                end

                @perms = auditd.file(@audit_file).permissions

                @perms.each do |perm|
                    describe perm do
                        it { should include 'x' }
                    end
                end
            else
                describe ('Audit line(s) for ' + @audit_file + ' exist') do
                    subject { audit_lines_exist }
                    it { should be true }
                end
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end

    control 'V-75787' do
        # TEST-WIP
        @audit_file = '/usr/bin/crontab'
        if package('auditd').installed?

            audit_lines_exist = !auditd.lines.index { |line| line.include?(@audit_file) }.nil?
            if audit_lines_exist
                describe auditd.file(@audit_file) do
                    its('permissions') { should_not cmp [] }
                    its('action') { should_not include 'never' }
                end

                @perms = auditd.file(@audit_file).permissions

                @perms.each do |perm|
                    describe perm do
                        it { should include 'x' }
                    end
                end
            else
                describe ('Audit line(s) for ' + @audit_file + ' exist') do
                    subject { audit_lines_exist }
                    it { should be true }
                end
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end

    control 'V-75789' do
        # TEST-WIP
        @audit_file = '/usr/sbin/pam_timestamp_check'
        if package('auditd').installed?

            audit_lines_exist = !auditd.lines.index { |line| line.include?(@audit_file) }.nil?
            if audit_lines_exist
                describe auditd.file(@audit_file) do
                    its('permissions') { should_not cmp [] }
                    its('action') { should_not include 'never' }
                end

                @perms = auditd.file(@audit_file).permissions

                @perms.each do |perm|
                    describe perm do
                        it { should include 'x' }
                    end
                end
            else
                describe ('Audit line(s) for ' + @audit_file + ' exist') do
                    subject { audit_lines_exist }
                    it { should be true }
                end
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end

    control 'V-75791' do
        # TEST-WIP
        if package('auditd').installed?
            if os.arch == 'x86_64'
                describe auditd.syscall('init_module').where { arch == 'b64' } do
                    its('action.uniq') { should eq ['always'] }
                    its('list.uniq') { should eq ['exit'] }
                end
            end
            describe auditd.syscall('init_module').where { arch == 'b32' } do
                its('action.uniq') { should eq ['always'] }
                its('list.uniq') { should eq ['exit'] }
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end

    control 'V-75793' do
        # TEST-WIP
        if package('auditd').installed?
            if os.arch == 'x86_64'
                describe auditd.syscall('finit_module').where { arch == 'b64' } do
                    its('action.uniq') { should eq ['always'] }
                    its('list.uniq') { should eq ['exit'] }
                end
            end
            describe auditd.syscall('finit_module').where { arch == 'b32' } do
                its('action.uniq') { should eq ['always'] }
                its('list.uniq') { should eq ['exit'] }
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end

    control 'V-75795' do
        # TEST-WIP
        if package('auditd').installed?
            if os.arch == 'x86_64'
                describe auditd.syscall('delete_module').where { arch == 'b64' } do
                    its('action.uniq') { should eq ['always'] }
                    its('list.uniq') { should eq ['exit'] }
                end
            end
            describe auditd.syscall('delete_module').where { arch == 'b32' } do
                its('action.uniq') { should eq ['always'] }
                its('list.uniq') { should eq ['exit'] }
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end

    control 'V-75807' do
        # TEST-OWIP
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

    control 'V-75819' do
        # TEST-OWIP
        options = {
            assignment_regex: /^\s*([^:]*?)\s*:\s*(.*?)\s*$/
        }
        describe.one do
            describe command('dmesg | grep NX').stdout.strip do
                it { should match /.+(NX \(Execute Disable\) protection: active)/ }
            end
            if file('/proc/cpuinfo').exist?
                describe parse_config_file('/proc/cpuinfo', options).flags.split(' ') do
                    it { should include 'nx' }
                end  
            end
        end
    end

    control 'V-80961' do
        # TEST-OWIP
        space_left_percent = input('space_left_percent')
        audit_log_path = input('log_file_dir')

        if directory(audit_log_path).exist?
            describe filesystem(audit_log_path) do
                its('percent_free') { should be >= space_left_percent }
            end
    
            partition_threshold_mb = (filesystem(audit_log_path).size_kb / 1024 * 0.25).to_i
            system_alert_configuration_mb = auditd_conf.space_left.to_i
    
            describe 'The space_left configuration' do
                subject { system_alert_configuration_mb }
                it { should >= partition_threshold_mb }
            end
           
        else
            it 'should have a log directory that exists' do
                dir_failure_message = "Audit directory: #{audit_log_path} does not exist"
                expect(directory(audit_log_path)).to exist, dir_failure_message
            end
        end
    end

    control 'V-80969' do
        # TEST-WIP
        @audit_file = '/usr/bin/chcon'
        if package('auditd').installed?

            audit_lines_exist = !auditd.lines.index { |line| line.include?(@audit_file) }.nil?
            if audit_lines_exist
                describe auditd.file(@audit_file) do
                    its('permissions') { should_not cmp [] }
                    its('action') { should_not include 'never' }
                end

                @perms = auditd.file(@audit_file).permissions

                @perms.each do |perm|
                    describe perm do
                        it { should include 'x' }
                    end
                end
            else
                describe ('Audit line(s) for ' + @audit_file + ' exist') do
                    subject { audit_lines_exist }
                    it { should be true }
                end
            end
        else
            it 'should have auditd installed' do
                failure_message = "Auditd is not installed"
                expect(package('auditd')).to be_installed, failure_message
            end
        end
    end
end
