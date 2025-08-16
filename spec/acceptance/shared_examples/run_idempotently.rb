shared_examples 'run idempotently' do
  block_on agents, run_in_parallel: true do |agent|
    case agent['platform']
    ## Run tests on Windows hosts
    when %r{windows-10}
      ## Run it twice and test for idempotency after reboot
      on(agent, puppet('agent', '-t'), acceptable_exit_codes: [2])
      agent.close
      info_msg('Sleeping for 30 seconds to allow reboot to occur')
      sleep(30)
      # Wait while agent reboots
      agent.wait_for_port(22)
      ## Second Puppet run
      on(agent, puppet('agent', '-t'), acceptable_exit_codes: [0])
    when %r{windows-11}
      ## Run it twice and test for idempotency after reboot
      on(agent, puppet('agent', '-t'), acceptable_exit_codes: [2])
      agent.close
      info_msg('Sleeping for 30 seconds to allow reboot to occur')
      sleep(30)
      # Wait while agent reboots
      agent.wait_for_port(22)
      ## Second Puppet run
      on(agent, puppet('agent', '-t'), acceptable_exit_codes: [0])
    end
  end
end
