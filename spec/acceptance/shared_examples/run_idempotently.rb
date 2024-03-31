shared_examples 'run idempotently' do
  agents.each_in_parallel do |agent|
    case agent['platform']
    ## Run tests on Windows hosts
    when %r{windows-10}
      ## Run it twice and test for idempotency after reboot
      on(agent, puppet('agent', '-t'), acceptable_exit_codes: [2])
      agent.close
      puts "\e[0;36m \nSleeping for 90 seconds to allow reboot to occur \e[0m\n"
      sleep(90)
      # Wait while agent reboots
      agent.wait_for_port(22)
      ## Second Puppet run
      on(agent, puppet('agent', '-t'), acceptable_exit_codes: [0])
    when %r{windows-11}
      ## Run it twice and test for idempotency after reboot
      on(agent, puppet('agent', '-t'), acceptable_exit_codes: [2])
      agent.close
      puts "\e[0;36m \nSleeping for 90 seconds to allow reboot to occur \e[0m\n"
      sleep(90)
      # Wait while agent reboots
      agent.wait_for_port(22)
      ## Second Puppet run
      on(agent, puppet('agent', '-t'), acceptable_exit_codes: [0])
    end
  end
end
