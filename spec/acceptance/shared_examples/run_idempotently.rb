shared_examples 'run idempotently' do
  block_on agents, run_in_parallel: true do |agent|
    case agent['platform']
    ## Run tests on Windows hosts
    when %r{windows-10|windows-11}
      # First Puppet run: catch changes (exit code 2 is normal for changes applied)
      on(agent, 'puppet agent -t', acceptable_exit_codes: [0, 2])
      
      # Close agent and wait for reboot if required
      agent.close
      info_msg('Sleeping for 30 seconds to allow reboot to occur')
      sleep 30
      
      # Wait while agent reboots
      agent.wait_for_port(22) # WinRM port for Windows
      
      # Second Puppet run: ensure idempotency
      on(agent, 'puppet agent -t', acceptable_exit_codes: [0])
    end
  end
end
