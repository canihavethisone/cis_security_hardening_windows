## - DNS Custom Fact for both LINUX and WINDOWS - ##
require 'resolv'
Facter.add(:networking_dns) do
  setcode do
    Resolv::DNS::Config.default_config_hash.each_with_object({}) do |(key, value), sub|
      unless value.nil?
        sub[key] = value
        sub
      end
    end
  end
end
